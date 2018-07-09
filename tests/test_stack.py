# -*- coding: utf-8 -*-
import yaml
from mock import patch
from moto import mock_cloudformation, mock_ec2, mock_sts
from troposphere import Output

import ekscli
from ekscli.stack import ClusterInfo, NodeGroup, ControlPlane, KubeConfig
from ekscli.utils import Status

cluster_endpoint = 'https://test.sk1.us-east-1.eks.amazonaws.com'
cluster_ca = 'BASE64STR'


def skip_cluster(self, cp_sg, role_arn):
    self.tpl.add_output(Output(self.OUTPUT_CP_ENDPOINT, Value=cluster_endpoint))
    self.tpl.add_output(Output(self.OUTPUT_CP_CA, Value=cluster_ca))


def skip_configmap(kubeconf, role):
    pass


@mock_cloudformation
def test_load_kubeconf():
    ci = ClusterInfo('poc', 'https://eks.awsamazon.com', '12345', vpc='vpc-12343565', sg='sg-123456',
                     subnets=['subnet-123435', 'subnet-234556'])
    ng = NodeGroup('nodes', cluster_info=ci, ami='ami-123456', keypair='test')
    ng.create()


@mock_cloudformation
@mock_ec2
@mock_sts
@patch.object(ekscli.stack.ControlPlane, '_create_eks_cluster_template', skip_cluster)
def test_create_control_plane():
    cp = ControlPlane('poc', role='eks-test')
    ci = cp.create()
    assert ControlPlane.RESOURCE_EKS_VPC.status == Status.created
    assert ci is not None
    assert ci.name == 'poc'
    assert ci.endpoint == cluster_endpoint


@mock_cloudformation
@mock_ec2
@mock_sts
@patch.object(ekscli.stack.ControlPlane, '_create_eks_cluster_template', skip_cluster)
@patch.object(ekscli.stack.NodeGroup, '_update_configmap', skip_configmap)
def test_create_cluster(tmpdir):
    cp = ControlPlane('test', role='eks-test', region='us-east-1')
    ci = cp.create()

    config = tmpdir.join('config')
    heptio = tmpdir.join('heptio')
    kc = KubeConfig(ci, config.strpath, user='aws', heptio_auth=heptio)
    kc.create()

    o = yaml.load(config.read())
    assert 'clusters' in o
    assert len(o['clusters']) == 1

    # moto cloudformation does not support AWS::EC2::SecurityGroupEgress
    # ng = NodeGroup('workers', cluster_info=ci, kubeconf=config.strpath, region='us-east-1')
    # ngi = ng.create()
    # assert ngi.name == 'workers'

