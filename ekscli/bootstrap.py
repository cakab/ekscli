from __future__ import absolute_import

import textwrap
from copy import deepcopy

import boto3
from future.utils import iteritems
from jinja2 import Environment

from ekscli import EKSCliException
from ekscli.stack import ClusterInfo, ControlPlane, KubeConfig, NodeGroup
from ec2_metadata import ec2_metadata

from ekscli.utils import which


class Kubelet(object):
    KUBELET_SVC_TEMPLATE = textwrap.dedent("""\
    [Unit]
    Description=Kubernetes Kubelet
    Documentation=https://k8s.io
    After=docker.service
    Requires=docker.service

    [Service]
    ExecStart={{ kube_exec }} \
    {{ kube_opts }}
    Restart=on-failure
    RestartSec=5

    [Install]
    WantedBy=multi-user.target
    """)

    KUBELET_OPTS = {
        'address': '0.0.0.0',
        'allow-privileged': 'true',
        'anonymous-auth': 'false',
        'cloud-provider': 'aws',
        'cluster-domain': 'cluster.local',
        'cni-bin-dir': '/opt/cni/bin',
        'cni-conf-dir': '/etc/cni/net.d',
        'container-runtime': 'docker',
        'feature-gates': 'RotateKubeletServerCertificate=true',
        'kubeconfig': '/var/lib/kubelet/kubeconfig',
        'network-plugin': 'cni',
        'pod-infra-container-image': '602401143452.dkr.ecr.REGION.amazonaws.com/eks/pause-amd64,3.1',
        'register-node': 'true',
    }

    def __init__(self, cluster_name=None, region=None, heptio_auth=None, kubelet_opts=None, max_pods=None,
                 cert_file='/etc/kubernetes/pki/ca.crt',
                 kubeconf_file='/var/lib/kubelet/kubeconfig',
                 kubelet_exec_file='/usr/bin/kubelet',
                 kubelet_svc_file='/etc/systemd/system/kubelet.service',
                 ):
        self.region = region or ec2_metadata.region
        self.cluster_name = cluster_name or self._get_cluster_name(self.region, ec2_metadata.instance_id)
        self.heptio = heptio_auth or which('heptio-authenticator-aws')
        self.cert_file = cert_file
        self.kubeconf_file = kubeconf_file
        self.kubelet_exec_file = kubelet_exec_file
        self.kubelet_svc_file = kubelet_svc_file
        self.kubelet_opts = deepcopy(self.KUBELET_OPTS)
        self.kubelet_opts.update(kubelet_opts)
        self.kubelet_opts['node-labels'] = ','.join(
            filter(None, ['node-role.kubernetes.io/node=', kubelet_opts.get('node-labels')]))
        self.max_pods = max_pods or NodeGroup.MAX_PODS.get(ec2_metadata.instance_type)
        if not self.max_pods:
            raise EKSCliException('Cannot find max number of pods per node based on the instance type. '
                                  'Please specify it with --max-pod option')

    def bootstrap(self):
        ci = self._get_cluster_info(self.cluster_name, self.region)
        self._create_cert(self.cert_file, ci.cert)
        self._create_kubeconf(self.kubeconf_file, ci, self.heptio)

        ip = ec2_metadata.private_ipv4
        self.kubelet_opts.update({
            'kubeconfig': self.kubeconf_file,
            'client-ca-file': self.cert_file,
            'max-pods': self.max_pods,
            'node-ip': ip,
            'cluster-dns': '172.20.0.10' if ip.startswith('10.') else '10.100.0.10',
        })
        self._create_kube_service(self.kubelet_svc_file, self.kubelet_exec_file, self.kubelet_opts)

    @staticmethod
    def _get_cluster_info(cluster_name, region):
        client = boto3.session.Session().client('eks', region_name=region)
        resp = client.describe_cluster(name=cluster_name)

        if not resp.get('cluster'):
            raise EKSCliException('Could not find EKS cluster[{}]'.format(cluster_name))

        c = resp.get('cluster')
        return ClusterInfo(cluster_name, endpoint=c.get('endpoint'),
                           cert=c.get('certificateAuthority', {}).get('data'),
                           vpc=c.get('resourcesVpcConfig', {}).get('vpcId'),
                           subnets=c.get('resourcesVpcConfig', {}).get('subnetIds'),
                           sg=c.get('resourcesVpcConfig', {}).get('securityGroupIds'))

    @staticmethod
    def _get_cluster_name(region, instance_id):
        ec2 = boto3.session.Session().resource('ec2', region_name=region)
        instance = ec2.Instance(instance_id)
        tags = list(filter(ControlPlane.CLUSTER_TAG_PATTERN.match, [t.get('Key', '') for t in instance.tags]))
        if not tags:
            raise EKSCliException('Cannot find the cluster name from ec2 instance tags.')

        return ControlPlane.CLUSTER_TAG_PATTERN.match(tags[0]).group(1)

    @staticmethod
    def _create_kubeconf(kubeconf, cluster_info, heptio):
        with open(kubeconf, 'w') as f:
            f.write(Environment().from_string(KubeConfig.KUBE_CONFIG_YAML).render(
                ci=cluster_info, user='kubelet', heptio=heptio))

    @staticmethod
    def _create_cert(cert_file, cert):
        with open(cert_file, 'w') as f:
            f.write(cert)

    @staticmethod
    def _create_kube_service(kubesvc_file, kubelet_file, kubelet_opts):
        opts = ' \\\n'.join(['  --{}={}'.format(k, v) if v else '  --{}'.format(k)
                             for k, v in sorted(iteritems(kubelet_opts), key=lambda opt: opt[0])])
        with open(kubesvc_file, 'w') as f:
            f.write(Environment().from_string(Kubelet.KUBELET_SVC_TEMPLATE).render(
                kube_exec=kubelet_file, kube_opts=opts))
