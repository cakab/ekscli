# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
import os
import random
import string
import textwrap
from collections import OrderedDict
from copy import copy, deepcopy

import boto3
import kubernetes
from awacs.aws import Statement, Allow, Principal, Policy
from awacs.sts import AssumeRole
from botocore.exceptions import ClientError
from future.utils import viewitems, listvalues
from jinja2 import Environment
from kubernetes.client.rest import ApiException
from netaddr import IPNetwork
from troposphere import Tags, Template, Output, Ref, GetAtt, Join, Base64
from troposphere.autoscaling import AutoScalingGroup, Tag, LaunchConfiguration
from troposphere.ec2 import VPC, SecurityGroup, Subnet, SecurityGroupIngress, SecurityGroupEgress, InternetGateway, \
    VPCGatewayAttachment, RouteTable, Route, SubnetRouteTableAssociation, SecurityGroupRule
from troposphere.eks import Cluster, ResourcesVpcConfig
from troposphere.iam import Role, InstanceProfile
from troposphere.policies import UpdatePolicy, AutoScalingRollingUpdate

import ekscli
from ekscli import EKSCliException
from ekscli.utils import get_stack, ResourceReporter, Status, delete_stack, load_kubeconf

LOG = logging.getLogger(ekscli.__app_name__)


class AWSSecurityGroupRule:
    def __init__(self, cidr='0.0.0.0', protocol='tcp', from_port=-1, to_port=-1, port=None):
        self.cidr = cidr
        self.protocol = protocol
        if port:
            self.from_port = port
            self.to_port = port
        else:
            self.from_port = from_port
            self.to_port = to_port


class Resource:
    def __init__(self, name, description, status, resource_id=None):
        self.name = name
        self.description = description
        self.status = status
        self.resource_id = resource_id

    def __copy__(self):
        return type(self)(self.name, self.description, self.status, self.resource_id)


class ClusterInfo:
    def __init__(self, name, endpoint=None, cert=None, vpc=None, subnets=[], sg=None):
        self.name = name
        self.endpoint = endpoint
        self.cert = cert
        self.vpc = vpc
        self.subnets = subnets
        self.sg = sg


class NodeGroupInfo:
    def __init__(self, name, instance=None, min_nodes=None, max_nodes=None, role=None):
        self.name = name
        self.instance = instance
        self.min = min_nodes
        self.max = max_nodes
        self.role = role

    def to_list(self):
        return [self.name, self.instance, self.min, self.max, self.role]


class ControlPlane:
    RESOURCE_EKS_VPC = Resource('VPC', 'VPC where the EKS runs on', Status.not_exist)
    RESOURCE_EKS_SUBNETS = []

    RESOURCE_CP_ROLE = Resource('MasterRole', 'EKS role for the control plane', Status.not_exist)
    RESOURCE_CP_SG = Resource('MasterSG', 'Security group for the control plane', Status.not_exist)
    RESOURCE_EKS_CLUSTER = Resource('Cluster', 'EKS cluster', Status.not_exist)

    # RESOURCE_VPC = 'VPC'
    RESOURCE_FORMAT_SUBNET = 'Subnet{}'
    RESOURCE_FORMAT_SUBNET_RTA = 'Subnet{}RouteTableAssociation'
    RESOURCE_VPC_INTERNET_GATEWAY = Resource('InternetGateway', 'VPC Internet gateway', Status.not_exist)
    RESOURCE_VPC_GATEWAY_ATTACHMENT = Resource('GatewayAttachment', 'VPC gateway attachment', Status.not_exist)
    RESOURCE_VPC_ROUTE_TABLE = Resource('VPCRouteTable', 'VPC Internet route table', Status.not_exist)
    RESOURCE_VPC_ROUTE = Resource('VPCRoute', 'VPC Internet route table', Status.not_exist)

    # Todo: use boto3.session.Session().get_available_regions('eks') once boto3 supports
    SUPPORTED_ZONES = {
        'us-east-1': ['us-east-1a', 'us-east-1b', 'us-east-1d'],
        'us-west-2': ['us-west-2a', 'us-west-2b', 'us-west-2c'],
    }
    SUPPORTED_KUBE_VERSIONS = ['1.10']

    OUTPUT_CP_ENDPOINT = 'MasterEndpoint'
    OUTPUT_CP_CA = 'MasterCA'
    OUTPUT_CP_SG = RESOURCE_CP_SG.name
    OUTPUT_VPC = RESOURCE_EKS_VPC.name
    OUTPUT_SUBNETS = 'EKSSubnets'

    TAG_CLUSTER = 'eks.k8s.io/cluster'

    def __init__(self, name, role=None, subnets=None, region=None, kube_ver=None, tags=[],
                 vpc_cidr=None, zones=None):
        self.name = name
        self.stack_name = 'eks-{}-cp'.format(name)
        self.tag_name = 'eks.{}.cp'.format(name)
        self.subnets = subnets
        self.tags = dict(t.split('=') for t in tags)
        self.tags.update({'Name': self.tag_name, self.TAG_CLUSTER: self.name})
        self.vpc = None
        self.role = role
        self.region = region.lower() if region else boto3.session.Session().region_name
        self.kube_ver = kube_ver if kube_ver else '1.10'
        self.tpl = None
        self.vpc_cidr = vpc_cidr or '192.168.0.0/8'
        self.zones = zones or self.SUPPORTED_ZONES.get(self.region)
        self.resources = []
        self.subnet_refs = None

    def create(self):
        self._validate_creation()

        self.tpl = Template()
        self.tpl.add_version('2010-09-09')
        self.tpl.add_description('CFN template to create an EKS cluster and affiliated resources.')

        self._create_vpc()
        self._create_eks_control_plane()
        tags = [{'Key': k, 'Value': v} for (k, v) in viewitems(self.tags)]
        cf = boto3.session.Session().resource('cloudformation')
        stack = cf.create_stack(StackName=self.stack_name, TemplateBody=self.tpl.to_yaml(),
                                Capabilities=['CAPABILITY_NAMED_IAM'], Tags=tags)

        reporter = ResourceReporter()
        stack = reporter.report_stack_creation(self.stack_name, self.resources, stack.stack_id)

        return self._stack_to_cluster_info(self.name, stack.outputs)

    def delete(self):
        ci = self.query()
        if not ci:
            return

        stacks = self.get_all_stacks()
        for s in stacks:
            for t in s.tags:
                if t.get('Key') == NodeGroup.TAG_NODEGROUP:
                    NodeGroup(name=t.get('Value'), cluster_info=ci).delete(stack=s)
                    break

        resources = [self.RESOURCE_EKS_CLUSTER, self.RESOURCE_CP_SG, self.RESOURCE_CP_ROLE]
        for i, subnet in enumerate(ci.subnets):
            sname = self.RESOURCE_FORMAT_SUBNET.format(i + 1)
            resources.append(Resource(sname, 'EKS VPC {}'.format(sname), Status.created, subnet))
        self.RESOURCE_EKS_VPC.resource_id = ci.vpc
        resources.append(self.RESOURCE_EKS_VPC)
        for r in resources:
            r.status = Status.created

        try:
            delete_stack(self.stack_name, resources)
        except EKSCliException as e:
            cf = boto3.session.Session().resource('cloudformation')
            stack = cf.Stack(self.stack_name)
            if not stack:
                raise e

            stack.delete()

    def query(self):
        cf = boto3.session.Session().resource('cloudformation')

        try:
            stack = cf.Stack(self.stack_name)
            return self._stack_to_cluster_info(self.name, stack.outputs)
        except ClientError as e:
            if 'Stack with id {} does not exist'.format(self.stack_name) in e.response.get('Error', {}).get('Message'):
                raise EKSCliException('The control plane of EKS cluster ({}) does not exist!'.format(self.name))

            raise EKSCliException(e)

    def get_all_stacks(self):
        cf = boto3.session.Session().resource('cloudformation')
        return [s for s in cf.stacks.all() for t in s.tags
                if t.get('Key') == self.TAG_CLUSTER and t.get('Value') == self.name]

    def get_all_nodegroup_stacks(self):
        return {t.get('Value'): s for s in self.get_all_stacks() for t in s.tags
                if t.get('Key') == NodeGroup.TAG_NODEGROUP}

    @staticmethod
    def _stack_to_cluster_info(name, outputs):
        if not outputs:
            return ClusterInfo(name)

        od = {o.get('OutputKey'): o.get('OutputValue') for o in outputs}
        return ClusterInfo(name, od.get(ControlPlane.OUTPUT_CP_ENDPOINT), od.get(ControlPlane.OUTPUT_CP_CA),
                           sg=od.get(ControlPlane.OUTPUT_CP_SG), vpc=od.get(ControlPlane.OUTPUT_VPC),
                           subnets=od.get(ControlPlane.OUTPUT_SUBNETS).split(','))

    def _validate_creation(self):
        stacks = get_stack(self.stack_name, ['DELETE_COMPLETE'])
        if len(stacks.get('unexpected')) > 0:
            raise EKSCliException(
                'CloudFormation stack (={}) of eks cluster already exists; delete it first.'.format(self.tag_name))

        if self.kube_ver not in self.SUPPORTED_KUBE_VERSIONS:
            raise EKSCliException('Error: Kubernetes Version (={}) is not supported in EKS'.format(self.kube_ver))

        if self.subnets:
            vpc_ids = self._get_vpc_ids_from_subnets(self.subnets)
            if len(set(vpc_ids)) != 1:
                raise EKSCliException('Subnets[{}] are not in the same vpc!'.format(','.join(self.subnets)))

            self.vpc = vpc_ids[0]
            self.RESOURCE_EKS_VPC.resource_id = self.vpc
            self.RESOURCE_EKS_VPC.status = Status.provided
            for i, sn in enumerate(self.subnets):
                r = Resource('Subnet{}'.format(i), description='Subnet{}'.format(i), status=Status.provided,
                             resource_id=sn)
                self.RESOURCE_EKS_SUBNETS.append(r)

    @staticmethod
    def _get_vpc_ids_from_subnets(subnets):
        resp = boto3.session.Session().client('ec2').describe_subnets(SubnetIds=subnets)
        return [subnet.get('VpcId') for subnet in resp.get('Subnets', [])]

    def _create_vpc(self):
        if self.vpc:
            self.tpl.add_output(Output(self.OUTPUT_VPC, Value=self.vpc))
            self.tpl.add_output(Output(self.OUTPUT_SUBNETS, Value=','.join(self.subnets)))
            return

        vpc = VPC(self.RESOURCE_EKS_VPC.name, CidrBlock=self.vpc_cidr, Tags=Tags(Name=self.tag_name))
        self.tpl.add_resource(vpc)
        gateway = self.tpl.add_resource(InternetGateway(self.RESOURCE_VPC_INTERNET_GATEWAY.name))
        self.tpl.add_resource(VPCGatewayAttachment(
            self.RESOURCE_VPC_GATEWAY_ATTACHMENT.name, VpcId=Ref(vpc), InternetGatewayId=Ref(gateway),
            DependsOn=gateway,
        ))
        rt = self.tpl.add_resource(RouteTable(
            self.RESOURCE_VPC_ROUTE_TABLE.name, VpcId=Ref(vpc), DependsOn=gateway,
            Tags=Tags(Name='public subnet', Network='public'),
        ))
        self.tpl.add_resource(Route(
            self.RESOURCE_VPC_ROUTE.name, RouteTableId=Ref(rt), DestinationCidrBlock='0.0.0.0/0',
            GatewayId=Ref(gateway),
        ))
        self.resources.extend(deepcopy([self.RESOURCE_EKS_VPC, self.RESOURCE_VPC_INTERNET_GATEWAY,
                                        self.RESOURCE_VPC_GATEWAY_ATTACHMENT, self.RESOURCE_VPC_ROUTE_TABLE,
                                        self.RESOURCE_VPC_ROUTE]))

        subnets = []
        vpc_network = IPNetwork(self.vpc_cidr)
        prefixlen = IPNetwork(self.vpc_cidr).prefixlen + (len(self.zones) - 1).bit_length()
        cidrs = list(vpc_network.subnet(prefixlen))
        for i, zone in enumerate(self.zones):
            sname = self.RESOURCE_FORMAT_SUBNET.format(i + 1)
            staname = self.RESOURCE_FORMAT_SUBNET_RTA.format(i + 1)
            subnet = self.tpl.add_resource(Subnet(
                sname, AvailabilityZone=zone, VpcId=Ref(vpc), CidrBlock=str(cidrs[i].cidr),
                Tags=Tags(Name='{}-{}'.format(self.name, str(i + 1)))
            ))
            self.resources.append(Resource(sname, 'EKS VPC {}'.format(sname), Status.not_exist))
            self.tpl.add_resource(SubnetRouteTableAssociation(
                staname, SubnetId=Ref(subnet), RouteTableId=Ref(rt)
            ))
            self.resources.append(Resource(staname, 'EKS VPC {}'.format(staname), Status.not_exist))
            subnets.append(subnet)

        self.subnet_refs = [Ref(s) for s in subnets]
        self.tpl.add_output(Output(self.OUTPUT_VPC, Value=Ref(vpc)))
        self.tpl.add_output(Output(self.OUTPUT_SUBNETS, Value=Join(',', self.subnet_refs)))

    def _create_eks_control_plane(self):
        account_id = boto3.client('sts').get_caller_identity().get('Account')
        r = copy(self.RESOURCE_CP_ROLE)
        if self.role:
            role_arn = 'arn:aws:iam::{}:role/{}'.format(account_id, self.role)
            r.status = Status.provided
            r.resource_id = role_arn
        else:
            role = self.tpl.add_resource(
                Role(self.RESOURCE_CP_ROLE.name, RoleName=self.tag_name,
                     AssumeRolePolicyDocument=Policy(Statement=[
                         Statement(Effect=Allow, Action=[AssumeRole],
                                   Principal=Principal('Service', ['eks.amazonaws.com'])),
                         Statement(Effect=Allow, Action=[AssumeRole],
                                   Principal=Principal('AWS', ['arn:aws:iam::{}:root'.format(account_id)])), ], ),
                     ManagedPolicyArns=['arn:aws:iam::aws:policy/AmazonEKSClusterPolicy',
                                        'arn:aws:iam::aws:policy/AmazonEKSServicePolicy']
                     ))
            role_arn = GetAtt(role, 'Arn')

        cp_sg = self.tpl.add_resource(SecurityGroup(
            self.RESOURCE_CP_SG.name,
            GroupDescription='Security Group applied to EKS cluster',
            VpcId=self.tpl.outputs.get(self.OUTPUT_VPC).resource.get('Value'),
            Tags=Tags(Name=self.tag_name)
        ))
        self.tpl.add_output(Output(self.OUTPUT_CP_SG, Value=Ref(self.OUTPUT_CP_SG)))

        self._create_eks_cluster_template(cp_sg, role_arn)
        self.resources.extend([r, copy(self.RESOURCE_CP_SG), copy(self.RESOURCE_EKS_CLUSTER)])

    # ToDo: remove this once moto support EKS in mock_cloudformation
    def _create_eks_cluster_template(self, cp_sg, role_arn):
        cluster = Cluster(self.RESOURCE_EKS_CLUSTER.name, Name=self.name, Version=self.kube_ver, RoleArn=role_arn,
                          ResourcesVpcConfig=ResourcesVpcConfig(SecurityGroupIds=[Ref(cp_sg)],
                                                                SubnetIds=self.subnets or self.subnet_refs))
        self.tpl.add_resource(cluster)
        self.tpl.add_output(Output(self.OUTPUT_CP_ENDPOINT, Value=GetAtt(cluster, 'Endpoint')))
        self.tpl.add_output(Output(self.OUTPUT_CP_CA, Value=GetAtt(cluster, 'CertificateAuthorityData')))


class KubeConfig:
    KUBE_CONFIG_YAML = textwrap.dedent("""\
    apiVersion: v1
    clusters:
    - cluster:
        server: {{ ci.endpoint }}
        certificate-authority-data: {{ ci.cert }}
      name: {{ ci.name }}
    contexts:
    - context:
        cluster: {{ ci.name }}
        user: {{ user | default('aws', True) }}
      name: {{ ci.name }}
    current-context: {{ ci.name }}
    kind: Config
    preferences: {}
    users:
    - name: {{ user | default('aws', True) }}
      user:
        exec:
          apiVersion: client.authentication.k8s.io/v1alpha1
          command: {{ heptio | default('heptio-authenticator-aws', True) }}
          args:
            - "token"
            - "-i"
            - "{{ ci.name }}"
    """)

    def __init__(self, cluster_info, kubeconf=None, user='aws', heptio_auth='heptio-authenticator-aws'):
        self.cluster_info = cluster_info
        self.user = user
        self.heptio = heptio_auth
        if kubeconf:
            self.kubeconf = kubeconf
        else:
            files = os.environ.get('KUBECONFIG', '~/.kube/config')
            self.kubeconf = os.path.expanduser(files.split(':')[0])

    def create(self):
        reporter = ResourceReporter()
        resource = Resource('kubeconf', 'Kubernetes configuration file', Status.not_exist, resource_id=self.kubeconf)
        reporter.progress(resource)
        try:
            if os.path.isfile(self.kubeconf):
                import oyaml as yaml
                with open(self.kubeconf, 'r') as cf:
                    kc = yaml.load(cf)

                clusters = self._get_components(kc, 'clusters')
                cs = [c for c in clusters if c.get('name') == self.cluster_info.name]
                if not cs:
                    clusters.append(OrderedDict([
                        ('cluster', OrderedDict([
                            ('certificate-authority-data', self.cluster_info.cert),
                            ('server', self.cluster_info.endpoint),
                        ])),
                        ('name', self.cluster_info.name),
                    ]))
                else:
                    for c in cs:
                        c['cluster']['server'] = self.cluster_info.endpoint
                        c['cluster']['certificate-authority-data'] = self.cluster_info.cert

                users = self._get_components(kc, 'users')
                us = [u for u in users if u.get('name') == self.user]
                if not us:
                    users.append(OrderedDict([
                        ('name', self.user),
                        ('user', OrderedDict([
                            ('exec', OrderedDict([
                                ('apiVersion', 'client.authentication.k8s.io/v1alpha1'),
                                ('command', self.heptio),
                                ('args', ['token', '-i', self.cluster_info.name])
                            ]))]))]))
                else:
                    for u in users:
                        u['user'] = OrderedDict([
                            ('exec', OrderedDict([
                                ('apiVersion', 'client.authentication.k8s.io/v1alpha1'),
                                ('command', self.heptio),
                                ('args', ['token', '-i', self.cluster_info.name])
                            ]))])

                contexts = self._get_components(kc, 'contexts')
                cs = [c for c in contexts if c.get('context', {}).get('cluster') == self.cluster_info.name
                      and c.get('context', {}).get('user') == self.user]
                if not cs:
                    contexts.append(OrderedDict([
                        ('context', OrderedDict([
                            ('cluster', self.cluster_info.name),
                            ('namespace', 'default'),
                            ('user', self.user),
                        ])),
                        ('name', self.cluster_info.name),
                    ]))

                kc['current-context'] = self.cluster_info.name

                with open(self.kubeconf, 'w') as cf:
                    cf.write(yaml.safe_dump(kc, default_flow_style=False))
            else:
                s = Environment().from_string(KubeConfig.KUBE_CONFIG_YAML).render(ci=self.cluster_info, user=self.user,
                                                                                  heptio=self.heptio)
                with open(self.kubeconf, 'w') as cf:
                    cf.write(s)

            resource.status = Status.created
            resource.resource_id = self.kubeconf
            reporter.succeed(resource)
        except Exception as e:
            resource.status = Status.failed
            reporter.fail(resource)
            raise EKSCliException(e)

        return

    @staticmethod
    def _get_components(kubeconf, components):
        if components not in kubeconf:
            kubeconf[components] = []

        return kubeconf.get(components)

    def _validate(self):
        pass


class NodeGroup:
    RESOURCE_NG_KEYPAIR = Resource('KeyName', 'Imported keypair name', Status.not_exist)
    RESOURCE_NG_ROLE = Resource('NodeGroupRole', 'Node EC2 instance role', Status.not_exist)
    RESOURCE_NG_PROFILE = Resource('NodeGroupProfile', 'Node EC2 instance profile', Status.not_exist)
    RESOURCE_NG_SG = Resource('NodeSG', 'Node EC2 security group', Status.not_exist)
    RESOURCE_NG_SG_INGRESS = Resource('NodeSGIngress', 'Node EC2 security group intra-nodes ingress',
                                      Status.not_exist)
    RESOURCE_NG_SG_CP_INGRESS = Resource('NodeSGFromCPIngress', 'Node EC2 security group control plane ingress',
                                         Status.not_exist)
    RESOURCE_CP_EGRESS_TO_NG = Resource('CPEgressToNodeSG',
                                        'Control plane security group egress to node security group',
                                        Status.not_exist)
    RESOURCE_CP_SG_INGRESS = Resource('CPIngressToNodeSG', 'Control plane security group ingress for pods',
                                      Status.not_exist)
    RESOURCE_NG_ASG = Resource('NodeAutoScalingGroup', 'Node autoscaling group', Status.not_exist)
    RESOURCE_NG_ASG_LC = Resource('NodeLaunchConfig', 'Node autoscaling group launch configuration',
                                  Status.not_exist)

    OUTPUT_KEYNAME = 'KeyName'

    TAG_NODEGROUP = 'k8s.io/cluster-autoscaler/node-template/label/ng'

    DEFAULT_AMI = {'us-east-1': 'ami-dea4d5a1', 'us-west-2': 'ami-73a6e20b'}
    USER_DATA = textwrap.dedent('''\
    #!/bin/bash -xe
    CA_CERTIFICATE_DIRECTORY=/etc/kubernetes/pki
    CA_CERTIFICATE_FILE_PATH=$CA_CERTIFICATE_DIRECTORY/ca.crt
    MODEL_DIRECTORY_PATH=~/.aws/eks
    MODEL_FILE_PATH=$MODEL_DIRECTORY_PATH/eks-2017-11-01.normal.json
    mkdir -p $CA_CERTIFICATE_DIRECTORY
    mkdir -p $MODEL_DIRECTORY_PATH
    curl -o $MODEL_FILE_PATH https://s3-us-west-2.amazonaws.com/amazon-eks/1.10.3/2018-06-05/eks-2017-11-01.normal.json
    aws configure add-model --service-model file://$MODEL_FILE_PATH --service-name eks
    aws eks describe-cluster --region={{region}} --name={{ci.name}} --query 'cluster.{certificateAuthorityData: certificateAuthority.data, endpoint: endpoint}' > /tmp/describe_cluster_result.json
    cat /tmp/describe_cluster_result.json | grep certificateAuthorityData | awk '{print $2}' | sed 's/[,"]//g' | base64 -d > $CA_CERTIFICATE_FILE_PATH
    MASTER_ENDPOINT=$(cat /tmp/describe_cluster_result.json | grep endpoint | awk '{print $2}' | sed 's/[,"]//g')
    INTERNAL_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
    sed -i s,MASTER_ENDPOINT,$MASTER_ENDPOINT,g /var/lib/kubelet/kubeconfig
    sed -i s,CLUSTER_NAME,{{ci.name}},g /var/lib/kubelet/kubeconfig
    sed -i s,REGION,{{region}},g /etc/systemd/system/kubelet.service
    sed -i s,MAX_PODS,{{max_pods}},g /etc/systemd/system/kubelet.service
    sed -i s,MASTER_ENDPOINT,$MASTER_ENDPOINT,g /etc/systemd/system/kubelet.service
    sed -i s,INTERNAL_IP,$INTERNAL_IP,g /etc/systemd/system/kubelet.service
    DNS_CLUSTER_IP=10.100.0.10
    if [[ $INTERNAL_IP == 10.* ]] ; then DNS_CLUSTER_IP=172.20.0.10; fi
    sed -i s,DNS_CLUSTER_IP,$DNS_CLUSTER_IP,g  /etc/systemd/system/kubelet.service
    sed -i s,CERTIFICATE_AUTHORITY_FILE,$CA_CERTIFICATE_FILE_PATH,g /var/lib/kubelet/kubeconfig
    sed -i s,CLIENT_CA_FILE,$CA_CERTIFICATE_FILE_PATH,g  /etc/systemd/system/kubelet.service
    systemctl daemon-reload
    systemctl restart kubelet
    /opt/aws/bin/cfn-signal -e $? --stack {{stack_name}} --resource {{ ng_asg }} --region {{region}}
    ''')

    MAP_ROLE = textwrap.dedent('''\
    - rolearn: {{ role }}
      username: system:node:{% raw %}{{EC2PrivateDNSName}}{% endraw %}
      groups:
        - system:bootstrappers
        - system:nodes
    ''')

    MAX_PODS = {
        'c4.large': 29, 'c4.xlarge': 58, 'c4.2xlarge': 58, 'c4.4xlarge': 234, 'c4.8xlarge': 234, 'c5.large': 29,
        'c5.xlarge': 58, 'c5.2xlarge': 58, 'c5.4xlarge': 234, 'c5.9xlarge': 234, 'c5.18xlarge': 737, 'i3.large': 29,
        'i3.xlarge': 58, 'i3.2xlarge': 58, 'i3.4xlarge': 234, 'i3.8xlarge': 234, 'i3.16xlarge': 737, 'm3.medium': 12,
        'm3.large': 29, 'm3.xlarge': 58, 'm3.2xlarge': 118, 'm4.large': 20, 'm4.xlarge': 58, 'm4.2xlarge': 58,
        'm4.4xlarge': 234, 'm4.10xlarge': 234, 'm5.large': 29, 'm5.xlarge': 58, 'm5.2xlarge': 58, 'm5.4xlarge': 234,
        'm5.12xlarge': 234, 'm5.24xlarge': 737, 'p2.xlarge': 58, 'p2.8xlarge': 234, 'p2.16xlarge': 234,
        'p3.2xlarge': 58, 'p3.8xlarge': 234, 'p3.16xlarge': 234, 'r3.xlarge': 58, 'r3.2xlarge': 58, 'r3.4xlarge': 234,
        'r3.8xlarge': 234, 'r4.large': 29, 'r4.xlarge': 58, 'r4.2xlarge': 58, 'r4.4xlarge': 234, 'r4.8xlarge': 234,
        'r4.16xlarge': 737, 't2.small': 8, 't2.medium': 17, 't2.large': 35, 't2.xlarge': 44, 't2.2xlarge': 44,
        'x1.16xlarge': 234, 'x1.32xlarge': 234
    }

    def __init__(self, name, cluster_info=None, region=None, subnets=[], tags={}, min_nodes=1, max_nodes=3,
                 role=None, sg_ingresses=[], desired_nodes=1, ami=None, instance_type='m4.large', ssh_public_key=None,
                 keypair=None, kubeconf=None):
        self.cluster = cluster_info
        self.subnets = subnets or self.cluster.subnets if self.cluster else []
        self.name = name
        self.tag_name = 'eks.{}.ng.{}'.format(self.cluster.name, self.name)
        self.stack_name = 'eks-{}-ng-{}'.format(self.cluster.name, self.name)
        self.tags = tags
        self.tags.update({'Name': self.tag_name,
                          ControlPlane.TAG_CLUSTER: self.cluster.name,
                          self.TAG_NODEGROUP: self.name})
        self.region = region
        self.role = role
        self.sg_igresses = sg_ingresses
        self.min = min_nodes
        self.max = max_nodes
        self.desired = desired_nodes
        self.ami = ami
        self.instance = instance_type
        self.ssh_public_key = ssh_public_key or '~/.ssh/id_rsa.pub'
        self.keypair = keypair
        self.keypair_imported = False
        self.ssh_public_key = ssh_public_key or os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa.pub")
        self.tpl = None
        self.use_public_ip = False
        self.kubeconf = kubeconf
        self.resources = None

    def create(self):
        self._validate_creation()
        self._create_cfn_template()
        tags = [{'Key': k, 'Value': v} for (k, v) in viewitems(self.tags)]

        cf = boto3.session.Session().resource('cloudformation')
        reporter = ResourceReporter()
        try:
            stack = cf.create_stack(StackName=self.stack_name, TemplateBody=self.tpl.to_yaml(),
                                    Capabilities=['CAPABILITY_NAMED_IAM'], Tags=tags)

            stack = reporter.report_stack_creation(self.stack_name, listvalues(self.resources), stack.stack_id)
            role = {o.get('OutputKey'): o.get('OutputValue') for o in stack.outputs}.get(self.RESOURCE_NG_ROLE.name)
        except Exception as e:
            ec2 = boto3.session.Session().resource('ec2')
            if self.keypair_imported:
                r = copy(self.RESOURCE_NG_KEYPAIR)
                r.resource_id = self.keypair
                ec2.KeyPair(self.keypair).delete()
                r.status = Status.deleted
                reporter.succeed(resource=r)

            raise e

        self._update_configmap(os.path.expanduser(self.kubeconf), role)
        return NodeGroupInfo(self.name, self.instance, self.min, self.max, role)

    def query(self, stack=None):
        if not stack:
            cf = boto3.session.Session().resource('cloudformation')
            stack = cf.Stack(self.stack_name)

        rss = {rs.logical_resource_id: rs for rs in stack.resource_summaries.all()}
        asg_name = rss.get(self.RESOURCE_NG_ASG.name).physical_resource_id
        asg_client = boto3.session.Session().client('autoscaling')
        resp = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name], MaxRecords=1)
        asg = resp.get('AutoScalingGroups')[0]
        self.min = asg.get('MinSize')
        self.max = asg.get('MaxSize')
        self.desired = asg.get('DesiredCapacity')

        lc_name = rss.get(self.RESOURCE_NG_ASG_LC.name).physical_resource_id
        resp = asg_client.describe_launch_configurations(LaunchConfigurationNames=[lc_name], MaxRecords=1)
        lc = resp.get('LaunchConfigurations')[0]
        self.instance = lc.get('InstanceType')

        odict = {o.get('OutputKey'): o.get('OutputValue') for o in stack.outputs}

        return NodeGroupInfo(self.name, self.instance, self.min, self.max, odict.get(self.RESOURCE_NG_ROLE.name))

    @staticmethod
    def _update_configmap(kubeconf, role):
        try:
            load_kubeconf(kubeconf)
            kube = kubernetes.client.CoreV1Api()
            namespace = 'kube-system'
            cm_name = 'aws-auth'
            cm = [item for item in kube.list_namespaced_config_map(namespace).items if item.metadata.name == cm_name]
            if not cm:
                cm = kubernetes.client.V1ConfigMap()
                roles = Environment().from_string(NodeGroup.MAP_ROLE).render(role=role)
                cm.metadata = kubernetes.client.V1ObjectMeta()
                cm.metadata.name = cm_name
                cm.data = {'mapRoles': roles}
                kube.create_namespaced_config_map(namespace=namespace, body=cm)
            else:
                import oyaml as yaml
                cm = cm[0]
                roles = yaml.load(cm.data.get('mapRoles', '[]'))
                node_roles = [r for r in roles if r.get('rolearn') == role]
                if not node_roles:
                    cm.data['mapRoles'] = '\n'.join(
                        [cm.data['mapRoles'], Environment().from_string(NodeGroup.MAP_ROLE).render(role=role)])

                kube.replace_namespaced_config_map('aws-auth', namespace, body=cm)
        except ApiException as e:
            raise EKSCliException('Exception during kubernetes ops: {}'.format(e))

    def _init_resources(self):
        self.resources = OrderedDict([(r.name, r) for r in deepcopy(
            [self.RESOURCE_NG_KEYPAIR, self.RESOURCE_NG_ROLE, self.RESOURCE_NG_PROFILE,
             self.RESOURCE_NG_SG, self.RESOURCE_NG_SG_INGRESS,
             self.RESOURCE_NG_SG_CP_INGRESS,
             self.RESOURCE_CP_SG_INGRESS, self.RESOURCE_CP_EGRESS_TO_NG,
             self.RESOURCE_NG_ASG_LC,
             self.RESOURCE_NG_ASG_LC, self.RESOURCE_NG_ASG])])

    def _validate_creation(self):
        ec2 = boto3.session.Session().resource('ec2')
        if not self.ami:
            self.ami = self.DEFAULT_AMI.get(self.region)
        elif '/' in self.ami:
            owner, name = tuple(self.ami.split('/'))
            images = list(ec2.images.filter(Owners=[owner], Filters=[{'Name': 'name', 'Values': [name]}]))
            if not images:
                raise EKSCliException('image [{}] does not exist.'.format(self.ami))
            self.ami = images[0]
        else:
            image = ec2.Image(self.ami)
            if not image:
                raise EKSCliException('AMI (id={}) does not exist.'.format(self.ami))

        public_subnet_num = len([s for s in self.subnets if self._is_subnet_public(s)])
        if public_subnet_num != len(self.subnets) and public_subnet_num != 0:
            raise EKSCliException('the subnets [{}] must be either all public or all private.'.format(self.subnets))
        if public_subnet_num == len(self.subnets):
            self.use_public_ip = True

        if not os.path.exists(self.kubeconf):
            raise EKSCliException('kubernetes configuration file ({}) does not exist.'.format(self.kubeconf))

        self._init_resources()

    def _create_cfn_template(self):
        self.tpl = Template()
        self.tpl.add_version('2010-09-09')
        self.tpl.add_description('CFN template to create an EKS node group and affiliated resources.')

        eks_tag = 'kubernetes.io/cluster/{}'.format(self.cluster.name)

        # r = copy(self.RESOURCE_NG_ROLE)
        r = self.resources.get(self.RESOURCE_NG_ROLE.name)
        if self.role:
            profile = InstanceProfile(
                self.RESOURCE_NG_PROFILE.name, InstanceProfileName=self.tag_name, Path='/', Roles=[self.role])
            account_id = boto3.session.Session().client('sts').get_caller_identity().get('Account')
            role_arn = 'arn:aws:iam::{}:role/{}'.format(account_id, self.role)
            self.tpl.add_output(
                Output(self.RESOURCE_NG_ROLE.name, Value=role_arn, Description='Node group role'))
            r.status = Status.provided
            r.resource_id = role_arn
        else:
            role = Role(
                self.RESOURCE_NG_ROLE.name, RoleName=self.tag_name,
                AssumeRolePolicyDocument=Policy(Statement=[
                    Statement(Effect=Allow, Action=[AssumeRole],
                              Principal=Principal('Service', ['ec2.amazonaws.com'])), ], ),
                ManagedPolicyArns=['arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy',
                                   'arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy',
                                   'arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly']
            )
            self.tpl.add_resource(role)
            profile = InstanceProfile(
                self.RESOURCE_NG_PROFILE.name, InstanceProfileName=self.tag_name, Path='/', Roles=[Ref(role)])
            self.tpl.add_output(
                Output(self.RESOURCE_NG_ROLE.name, Value=GetAtt(role, 'Arn'), Description='Node group role'))

        self.tpl.add_resource(profile)
        # self.resources.extend([r, copy(self.RESOURCE_NG_PROFILE)])

        if self.sg_igresses:
            sg = SecurityGroup(
                self.RESOURCE_NG_SG.name, VpcId=self.cluster.vpc, Tags=Tags({'Name': self.tag_name, eks_tag: 'owned'}),
                GroupDescription='Security Group applied to the EKS node group',
                SecurityGroupIngress=[SecurityGroupRule(IpProtocol=r.protocol, FromPort=r.from_port, ToPort=r.to_port,
                                                        CidrIp=r.cidr) for r in self.sg_igresses]
            )
        else:
            sg = SecurityGroup(
                self.RESOURCE_NG_SG.name, VpcId=self.cluster.vpc, Tags=Tags({'Name': self.tag_name, eks_tag: 'owned'}),
                GroupDescription='Security Group applied to the EKS node group',
            )
        self.tpl.add_resource(sg)

        self.tpl.add_resource(SecurityGroupIngress(
            self.RESOURCE_NG_SG_INGRESS.name, DependsOn=sg, Description='Allow node to communicate with each other',
            GroupId=Ref(sg), SourceSecurityGroupId=Ref(sg), IpProtocol='-1', FromPort=0, ToPort=65535
        ))

        self.tpl.add_resource(SecurityGroupIngress(
            self.RESOURCE_NG_SG_CP_INGRESS.name, DependsOn=sg,
            Description='Allow kubelet and pods on the nodes to receive communication from the cluster control plane',
            GroupId=Ref(sg), SourceSecurityGroupId=self.cluster.sg, IpProtocol='tcp', FromPort=1025, ToPort=65535
        ))

        self.tpl.add_resource(SecurityGroupEgress(
            self.RESOURCE_CP_EGRESS_TO_NG.name, DependsOn=sg,
            Description='Allow the cluster control plane to communicate with nodes kubelet and pods',
            GroupId=self.cluster.sg, DestinationSecurityGroupId=Ref(sg), IpProtocol='tcp', FromPort=1025, ToPort=65535
        ))

        self.tpl.add_resource(SecurityGroupIngress(
            self.RESOURCE_CP_SG_INGRESS.name, DependsOn=sg,
            Description='Allow pods to communicate with the cluster API Server',
            GroupId=self.cluster.sg, SourceSecurityGroupId=Ref(sg), IpProtocol='tcp', FromPort=443, ToPort=443
        ))

        # keypair
        ec2 = boto3.session.Session().resource('ec2')
        r = self.resources.get(self.RESOURCE_NG_KEYPAIR.name)
        if not self.keypair:
            keyname = 'eks{}'.format(''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(5)))
            with open(self.ssh_public_key, 'rb') as f:
                ec2.import_key_pair(KeyName=keyname, PublicKeyMaterial=f.read())
            self.keypair = keyname
            self.keypair_imported = True
            self.tpl.add_output(Output(self.OUTPUT_KEYNAME, Value=self.keypair, Description='Imported kaypair name'))
            r.status = Status.created
        else:
            r.status = Status.provided

        r.resource_id = self.keypair
        # self.resources.insert(0, r)

        # auto-scaling group and launch configuration
        userdata = [line + '\n' for line in
                    Environment().from_string(self.USER_DATA).render(
                        ci=self.cluster, ng_asg=self.RESOURCE_NG_ASG.name, stack_name=self.stack_name,
                        max_pods=self.MAX_PODS.get(self.instance), region=self.region).split('\n')]

        lc = LaunchConfiguration(
            self.RESOURCE_NG_ASG_LC.name, AssociatePublicIpAddress=self.use_public_ip, IamInstanceProfile=Ref(profile),
            ImageId=self.ami, InstanceType=self.instance, KeyName=self.keypair, SecurityGroups=[Ref(sg)],
            UserData=Base64(Join('', userdata)))
        self.tpl.add_resource(lc)

        self.tpl.add_resource(AutoScalingGroup(
            self.RESOURCE_NG_ASG.name, DesiredCapacity=self.desired, MinSize=self.min, MaxSize=self.max,
            LaunchConfigurationName=Ref(lc), VPCZoneIdentifier=self.subnets,
            Tags=[Tag('Name', self.tag_name, True), Tag(eks_tag, 'owned', True)],
            UpdatePolicy=UpdatePolicy(
                AutoScalingRollingUpdate=AutoScalingRollingUpdate(MinInstancesInService=1, MaxBatchSize=1))))

    @staticmethod
    def _is_subnet_public(subnet):
        ec2 = boto3.session.Session().resource('ec2')
        rts = list(ec2.route_tables.filter(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet]}]))
        for rt in rts:
            for r in rt.routes:
                if r.gateway_id and r.gateway_id.startswith('igw-'):
                    return True

        return False

    def delete(self, stack=None):
        if not stack:
            cf = boto3.session.Session().resource('cloudformation')
            stack = cf.Stack(self.stack_name)

        odict = {o.get('OutputKey'): o.get('OutputValue') for o in stack.outputs}
        key_name = odict.get(self.OUTPUT_KEYNAME)

        self._init_resources()
        success = False
        r = self.resources.pop(self.RESOURCE_NG_KEYPAIR.name)
        try:
            success = delete_stack(self.stack_name, list(reversed(listvalues(self.resources))), stack=stack)
        finally:
            if key_name and success:
                reporter = ResourceReporter()
                boto3.session.Session().resource('ec2').KeyPair(key_name).delete()
                r.resource_id = key_name
                r.status = Status.deleted
                reporter.succeed(r)
