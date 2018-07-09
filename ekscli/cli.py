# -*- coding: utf-8 -*-

"""EKS command line interface"""
from __future__ import absolute_import

import functools
import logging
import os
import re
import sys

import boto3
import click
from future.utils import iteritems
from tabulate import tabulate

import ekscli
from ekscli.stack import ControlPlane, KubeConfig, NodeGroup, ClusterInfo, AWSSecurityGroupRule
from ekscli.thirdparty.click_alias import ClickAliasedGroup
from ekscli.utils import which, MutuallyExclusiveOption

LOG = logging.getLogger(ekscli.__app_name__)

__log_levels = [logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG, logging.NOTSET]


def config_logger(ctx, param, value):
    if value > 4:
        raise click.BadParameter('Set verbosity between -v and -vvvv')

    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    LOG.addHandler(handler)
    LOG.setLevel(__log_levels[value])


def validate_region(ctx, param, value):
    if value:
        boto3.setup_default_session(region_name=value)
        region = value
    else:
        region = boto3.session.Session().region_name
        LOG.info('Using the system default AWS region: {}'.format(region))

    if region not in ControlPlane.SUPPORTED_ZONES:
        raise click.BadParameter('EKS not supported in this region - {}'.format(region))

    return region


def validate_subnetes(ctx, param, value):
    if not value:
        return []

    try:
        subnets = value.split(',')
        invalids = [s for s in subnets if not re.match(r'(subnet-[a-f0-9]{8})', s)]
        if len(invalids):
            raise click.BadParameter('these subnet ids are invalid: {}'.format(','.join(invalids)))

        return subnets
    except ValueError:
        raise click.BadParameter('subnets should be a valid subnet id list.')


def validate_security_group_rule(ctx, param, value):
    if not value:
        return None

    try:
        # rule = namedtuple('rule', ['protocol', 'cidr', 'from_port', 'to_port'])
        rules = [dict(tuple(x.split('=')) for x in v.split(',')) for v in value]
        ingresses = [AWSSecurityGroupRule(cidr=r.get('cidr', '0.0.0.0/0'),
                                          protocol=r.get('protocol', 'tcp'),
                                          from_port=r.get('from', -1),
                                          to_port=r.get('to', -1),
                                          port=r.get('port'))
                     for r in rules]
        return ingresses
    except Exception as e:
        raise click.BadParameter('ingress rule should be in the form as key-value pair delimited with comma')


def validate_tags(ctx, param, value):
    if not value:
        return {}

    try:
        # tags = re.findall(r'([^=]+)=([^=]+)(?:,|$)', value)
        bits = [x.rsplit(',', 1) for x in value.split('=')]
        kv = [(bits[i][-1], bits[i + 1][0]) for i in range(len(bits) - 1)]
        invalids = [t for t in kv if not t[0] or not t[1]]
        if len(invalids):
            raise ValueError()

        return dict(kv)
    except ValueError:
        raise click.BadParameter('tags should be in the form of k1=v11,k2=v2')


def validate_heptio_authenticator(ctx, param, value):
    executable = value if value else 'heptio-authenticator-aws{}'.format('.exe' if os.name == 'nt' else '')
    path = which(executable)
    if not path:
        raise click.BadParameter('{} does not exist in environment paths or un-executable.'.format(executable))

    LOG.info('Use {} for heptio-authenticator-aws'.format(path))
    return executable


def common_options(func):
    @click.option('--name', '-n', envvar='EKS_CLUSTER_NAME', required=True,
                  help='A regional unique name of the EKS cluster. Overrides EKS_CLUSTER_NAME environment variable.')
    @click.option('--region', type=str, callback=validate_region, help='The AWS region to create the EKS cluster.')
    @click.option('-v', '--verbosity', callback=config_logger, count=True,
                  help='Log level; -v for WARNING, -vv INFO,  -vvv DEBUG and -vvvv NOTSET.')
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


@click.group()
@click.pass_context
def eks(ctx):
    """A simple and flexible command-line tool for AWS EKS management"""
    pass


@eks.command()
def version():
    """Show the EKS cli version info"""
    print('Version '.format(ekscli.__version__))


@eks.group(invoke_without_command=True, no_args_is_help=True, cls=ClickAliasedGroup,
           short_help='Create an EKS resource: a cluster or node group')
@click.pass_context
def create(ctx):
    """Create an EKS component: a cluster or node group"""
    pass


@eks.group(invoke_without_command=True, no_args_is_help=True, cls=ClickAliasedGroup)
@click.pass_context
def get(ctx):
    """Display EKS resource information"""
    pass


@eks.group(invoke_without_command=True, no_args_is_help=True, cls=ClickAliasedGroup)
@click.pass_context
def delete(ctx):
    """Delete an EKS resource: cluster or node group"""
    pass


@eks.group(invoke_without_command=True, no_args_is_help=True)
@click.pass_context
def export(ctx):
    """Export configuration from an EKS cluster"""
    pass


@create.command(name='cluster')
@common_options
@click.option('--cp-role', type=str, help='The existing EKS role for the control plane.')
@click.option('--subnets', type=str, callback=validate_subnetes,
              help='The existing subnets for the EKS cluster and node groups.')
@click.option('--vpc-cidr', type=str, default='192.168.0.0/16', cls=MutuallyExclusiveOption,
              mutex_group=['subnets', 'vpc_cidr'], help='The VPC CIDR block')
@click.option('--zones', type=str, cls=MutuallyExclusiveOption,
              mutex_group=['subnets', 'zones'], help='Availability zones where to deploy EKS cluster.')
@click.option('--tags', type=str, callback=validate_tags,
              help='Tags for the cluster; delimited by comma as: Key0=Value0,Key1=Value1.')
@click.option('--kubeconf', type=str,
              help='Kubernetes config file; if not set, KUBECONFIG or ~/.kube/config will be used.')
@click.option('--username', type=str, default='aws', help='Username specified in kube config file for this cluster.')
@click.option('--heptio-auth', type=str, callback=validate_heptio_authenticator,
              help='The path to Heptio AWS authenticator.')
@click.option('--cp-only', is_flag=True, default=False, help='To create EKS control plane only without node groups.')
@click.option('--node-name', type=str, default='workers', cls=MutuallyExclusiveOption,
              mutex_group=['cp_only', 'node-name'], help='The node group name')
@click.option('--node-role', type=str, cls=MutuallyExclusiveOption, mutex_group=['cp_only', 'node-role'],
              help='Additional roles for the node group')
@click.option('--node-sg-ingress', type=str, cls=MutuallyExclusiveOption, mutex_group=['cp_only', 'node-sg-ingress'],
              multiple=True, callback=validate_security_group_rule,
              help='Additional security group ingresses for the node group')
@click.option('--node-min', type=int, default=1, cls=MutuallyExclusiveOption,
              mutex_group=['cp_only', 'node-min'], help='The min size of the node group')
@click.option('--node-max', type=int, default=3, cls=MutuallyExclusiveOption,
              mutex_group=['cp_only', 'node-max'], help='The max size of the node group')
@click.option('--node-subnets', type=str, callback=validate_subnetes,
              help='The existing subnets to create node groups. Default, all subnets where EKS cluster is deployed.')
@click.option('--keyname', type=str, cls=MutuallyExclusiveOption, mutex_group=['cp_only', 'keyname', 'ssh_public_key'],
              help='To use an existing keypair name in AWS for node groups')
@click.option('--ssh-public-key', type=str, cls=MutuallyExclusiveOption,
              mutex_group=['cp_only', 'keyname', 'ssh_public_key'],
              help='To create a keypair used by node groups with an existing SSH public key.')
@click.option('--ami', type=str, cls=MutuallyExclusiveOption, mutex_group=['cp_only', 'ami'],
              help='AWS AMI id or location')
@click.option('--yes', '-y', is_flag=True, default=False, help='Run ekscli without any confirmation prompt.')
@click.pass_context
def create_cluster(ctx, name, region, verbosity,
                   cp_role, subnets, tags, vpc_cidr, zones, kubeconf, username, heptio_auth, cp_only, node_name,
                   node_role, node_sg_ingress, node_min, node_max, node_subnets, keyname, ssh_public_key, ami, yes):
    """Create an EKS cluster"""
    if node_subnets and not subnets:
        print('If node subnets are specified, the cluster subnets must appear!')
        exit(1)
    elif node_subnets and subnets:
        s = [ns for ns in node_subnets if ns not in subnets]
        if s:
            print('[{}] not one of the cluster subnets.'.format(','.join(s)))
            exit(1)

    if not kubeconf:
        files = os.environ.get('KUBECONFIG', '~/.kube/config')
        kubeconf = os.path.expanduser(files.split(':')[0])
        if not yes:
            if not click.confirm('Are you sure to create the EKS cluster in '
                                 'region[{}] with kubeconfig[{}]'.format(region, kubeconf)):
                exit(0)

    cp = ControlPlane(name, subnets=subnets, role=cp_role, region=region, tags=tags,
                      vpc_cidr=vpc_cidr, zones=zones)
    cluster_info = cp.create()
    kc = KubeConfig(cluster_info, kubeconf, user=username, heptio_auth=heptio_auth)
    kc.create()

    if cp_only:
        LOG.info('To create EKS cluster control plane only.')
        return

    ng = NodeGroup(node_name, cluster_info=cluster_info, keypair=keyname, region=region, ami=ami, subnets=node_subnets,
                   kubeconf=kubeconf, role=node_role, sg_ingresses=node_sg_ingress, min_nodes=node_min,
                   max_nodes=node_max, ssh_public_key=ssh_public_key)
    ng.create()


@export.command(name='kubeconfig')
@common_options
@click.option('--kubeconf', type=str,
              help='Kubernetes config file; if not set, KUBECONFIG or ~/.kube/config will be used.')
@click.option('--username', type=str, help='Username specified in Kubernetes conf file for this cluster', default='aws')
@click.option('--heptio-auth', type=str, callback=validate_heptio_authenticator,
              help='The path to Heptio AWS authenticator.')
@click.pass_context
def export_kubeconfig(ctx, name, region, verbosity, kubeconf, username, heptio_auth):
    """Export Kubernetes configuration for kubectl"""
    cp = ControlPlane(name, region=region)
    cluster_info = cp.query()
    kc = KubeConfig(cluster_info, kubeconf, user=username, heptio_auth=heptio_auth)
    kc.create()


@create.command(name='nodegroup', aliases=['ng'])
@common_options
@click.option('--node-name', required=True, help='The node group name.')
@click.option('--tags', type=str, callback=validate_tags,
              help='Tags for all resources; delimited by comma as: Key0=Value0,Key1=Value1.')
@click.option('--kubeconf', type=str,
              help='Kubernetes config file; if not set, KUBECONFIG or ~/.kube/config will be used.')
@click.option('--node-role', type=str, help='Additional roles for the node group')
@click.option('--node-sg-ingress', type=str, callback=validate_security_group_rule, multiple=True,
              help='Additional security group ingresses for the node group')
@click.option('--node-min', type=int, default=1, help='The min size of the node group')
@click.option('--node-max', type=int, default=3, help='The max size of the node group')
@click.option('--node-subnets', type=str, callback=validate_subnetes,
              help='The existing subnets to create this node groups.')
@click.option('--keyname', type=str, help='To use an existing keypair name in AWS for node groups',
              cls=MutuallyExclusiveOption, mutex_group=['keyname', 'ssh_public_key'])
@click.option('--ssh-public-key', type=str,
              help='To create a keypair used by node groups with an existing SSH public key.',
              cls=MutuallyExclusiveOption, mutex_group=['keyname', 'ssh_public_key'])
@click.option('--ami', type=str, help='AWS AMI id or location')
@click.option('--yes', '-y', is_flag=True, default=False, help='Run ekscli without any confirmation prompt.')
@click.pass_context
def create_nodegroup(ctx, name, node_name, region, verbosity, node_subnets, tags, kubeconf, node_min, node_max,
                     node_role, node_sg_ingress, keyname, ssh_public_key, ami, yes):
    """Create a node group in an existing EKS cluster"""
    cp = ControlPlane(name, region=region)
    cluster_info = cp.query()

    if not kubeconf:
        files = os.environ.get('KUBECONFIG', '~/.kube/config')
        kubeconf = os.path.expanduser(files.split(':')[0])
        if not yes:
            if not click.confirm('Are you sure to create the EKS cluster in '
                                 'region[{}] with kubeconfig[{}]'.format(region, kubeconf)):
                exit(0)
    ng = NodeGroup(node_name, cluster_info=cluster_info, region=region, ami=ami, keypair=keyname, subnets=node_subnets,
                   role=node_role, sg_ingresses=node_sg_ingress, ssh_public_key=ssh_public_key, tags=tags,
                   kubeconf=kubeconf, min_nodes=node_min, max_nodes=node_max)
    ng.create()


@get.command(name='cluster')
@common_options
@click.pass_context
def get_cluster(ctx, name, region, verbosity):
    """Display the information about the EKS cluster's control plane.
    """
    cp = ControlPlane(name, region=region)
    ci = cp.query()
    headers = ['NAME', 'ENDPOINT', 'VPC', 'SUBNETS']
    print(tabulate([[ci.name, ci.endpoint, ci.vpc, ','.join(ci.subnets)]], headers, tablefmt='plain'))


@get.command(name='nodegroup', aliases=['nodegroups', 'ng'])
@common_options
@click.argument('node-group-names', nargs=-1)
@click.pass_context
def get_ng(ctx, name, region, verbosity, node_group_names):
    """Display one or more node groups by names.
    If no node group names specified, ekscli will display all node groups in the current EKS cluster
    """
    cp = ControlPlane(name, region=region)
    ci = cp.query()

    if node_group_names:
        ngis = [NodeGroup(name, ci).query().to_list() for name in node_group_names]
    else:
        stacks = cp.get_all_nodegroup_stacks()
        ngis = [NodeGroup(name, ci).query(s).to_list() for (name, s) in list(iteritems(stacks))]

    headers = ['NAME', 'INSTANCETYPE', 'MIN', 'MAX', 'ROLE']
    print(tabulate(ngis, headers, tablefmt='plain'))


@delete.command(name='cluster')
@common_options
@click.confirmation_option('--yes', '-y', help='Are you sure to delete this cluster and associated node groups?')
@click.pass_context
def delete_cluster(ctx, name, region, verbosity):
    """Delete an EKS cluster (including its node groups)"""
    cp = ControlPlane(name, region=region)
    cp.delete()


@delete.command(name='nodegroup', aliases=['ng'])
@common_options
@click.option('--node-name', required=True, help='The node group name.')
@click.option('--kubeconf', type=str,
              help='Kubernetes config file; if not set, KUBECONFIG or ~/.kube/config will be used.')
@click.confirmation_option('--yes', '-y', help='Are you sure to delete this node group?')
@click.pass_context
def delete_nodegroup(ctx, name, region, verbosity, node_name, kubeconf):
    """Delete an EKS node grup"""
    ng = NodeGroup(node_name, ClusterInfo(name), region=region, kubeconf=kubeconf)
    ng.delete()


def cli():
    try:
        eks()
    except Exception as e:
        click.echo('Error: {}'.format(e))
        return 1


if __name__ == "__main__":
    sys.exit(cli())
