=======
ekscli
=======
|Build Status| |Docs| |Version| |License|

.. |Build Status| image:: https://api.travis-ci.com/cakab/ekscli.svg?branch=master
    :target: https://travis-ci.org/cakab/ekscli
    :alt: Build Status

.. |Docs| image:: https://readthedocs.org/projects/ekscli/badge/?version=latest
        :target: https://ekscli.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status

.. |Version| image:: https://img.shields.io/pypi/v/ekscli.svg
        :target: https://pypi.python.org/pypi/ekscli

.. |License| image:: https://img.shields.io/badge/License-MIT-yellow.svg
    :target: https://opensource.org/licenses/MIT
    :alt: License MIT


A simple and flexible command-line tool for AWS EKS management


* Free software: MIT license
* Documentation: https://ekscli.readthedocs.io.

-------------
Prerequisites
-------------
* Available AWS credentials (configured as `boto3 <https://boto3.readthedocs.io/en/latest/guide/configuration.html>`_)
* Heptio authenticator binary (Section ``To install heptio-authenticator-aws for Amazon EKS`` in `AWS EKS User Guide <https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html#eks-prereqs>`_)
* [Optional] kubectl (1.10 and later) for kubernetes cluster operations

-----------
Quick Start
-----------
~~~~~~~~~~~~
Installation
~~~~~~~~~~~~
As easy as the standard python way by using `pip <https://pip.pypa.io/en/latest/>`_.

.. code-block:: bash

    $ pip install ekscli

Optionally, after installation, command-completion can be achieved with:

.. code-block:: bash

    $ eval "$(_EKS_COMPLETE=source eks)"

~~~~~~~~~~~~
Use ECKCLI
~~~~~~~~~~~~
Note: AWS fees will be charged in your account for the AWS resources created by ekscli.

| The simplest way to create a cluster by running ``ekscli`` with almost everything default.
| This will create an EKS cluster including the control plane (managed master by AWS), a node group and a ``kubectl`` configuration file (``KUBECONFIG`` or ``$HOME/.kube/config``).

.. code-block:: bash

    $ eks create cluster --name=dev

    # EKS cluster name can be set as an environment variable
    $ export EKS_CLUSTER_NAME=dev
    $ eks create cluster

To create the EKS cluster's control plane (master) only:

.. code-block:: bash

    $ eks create cluster --name=dev --cp-only

To create the EKS cluster's control plane (master) with existing subnets of a VPC, a predefined IAM role, an existing EC2 KeyPair etc.:

.. code-block:: bash

    $ eks create cluster --name=dev --cp-only \
      --subnets=subnet-1234567,subnet-abcdef1 \
      --cp-role eks-default-role \
      --region us-west-2 \
      --kubconfig ./dev.conf \
      --heptio-auth /tmp/heptio-auth-aws \
      --keyname dev \
      --node-sg-ingress port=22,cidr=10.0.0.0/8 \
      --tags Env=dev,Project=eks-poc

The simplest way to create a node group

.. code-block:: bash

    $ eks create node-group --name=dev --node-name=workers

To create a node group with more options

.. code-block:: bash

    $ eks create node-group --name=dev --node-name=another \
      --node-role=eks-worker-s3 \
      --node-subnets=subnet-1234567 \
      --node-min=1 \
      --node-max=10
      --node-sg-ingress port=22,cidr=10.0.0.0/8 \
      --node-sg-ingress protocol=tcp,from=8080,to=8088,cidr=0.0.0.0/0 \
      --region us-west-2 \
      --kubconfig ./dev.conf \
      --heptio-auth /tmp/heptio-auth-aws \
      --keyname dev \
      --tags Env=dev,Project=eks-poc

To activate Bash auto-completion for ekscli

.. code-block:: bash

    $ eval "$(_EKS_COMPLETE=source eks)"

--------
Features
--------

* Simple and concise command line interface
* Flexible configuration
* Plain vanilla EKS cluster without unrequired resources running Kubernetes clusters
* EKS resources managed by AWS `CloudFormation <https://aws.amazon.com/cloudformation/>`_
* Command line auto-completion supported for Bash and Zsh

--------
Roadmap
--------
* Output cluster information to different formats: yaml, json
* Update the cluster and node groups
* Create from templatable configuration files
