# -*- coding: utf-8 -*-

""" Utility helpers """
from __future__ import absolute_import

import json
import logging
import os
import time
from enum import Enum

import boto3
import click
import yaml
from future.moves import subprocess
from future.utils import iteritems
from halo import Halo
from kubernetes.client import Configuration
from kubernetes.config.kube_config import KubeConfigLoader

import ekscli
from ekscli import EKSCliException

LOG = logging.getLogger(ekscli.__app_name__)


# py2 compatibility
def which(executable):
    path = os.getenv('PATH')

    for p in path.split(os.path.pathsep):
        p = os.path.join(p, executable)
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p


def get_stack(stack_name, expected_states):
    stacks = [s for s in boto3.resource('cloudformation').stacks.all() if s.stack_name == stack_name]
    return {
        'expected': [s for s in stacks if s.stack_status in expected_states],
        'unexpected': [s for s in stacks if s.stack_status not in expected_states]
    }


def delete_stack(stack_name, resources, stack=None):
    if not stack:
        stacks = get_stack(stack_name, ['DELETE_COMPLETE'])
        if len(stacks.get('unexpected')) == 0:
            LOG.warning('the stack of eks cluster [name={}] does not exists. Nothing to do.'.format(stack_name))
            return False
        elif len(stacks.get('unexpected')) > 1:
            raise EKSCliException('More than one EKS stack exists!')
        stack = stacks.get('unexpected')[0]

    cf = boto3.session.Session().resource('cloudformation')
    stack = cf.Stack(stack.stack_id)
    states = {rs.logical_resource_id: rs for rs in stack.resource_summaries.all()}
    for r in resources:
        if r.name in states:
            r.status = Status.created
            r.resource_id = states.get(r.name).physical_resource_id
        else:
            r.status = Status.provided

    if stack.stack_status not in ['DELETE_IN_PROGRESS']:
        stack.delete()

    reporter = ResourceReporter()
    reporter.report_stack_deletion(stack_name, resources, stack.stack_id)

    return True


# Todo: https://github.com/kubernetes-client/python/issues/514
def load_kubeconf(config_file):
    with open(config_file, 'r') as f:
        config = yaml.load(f)
        user = [user for user in config['users'] if user['name'] == 'aws'][0]['user']
        command = [user['exec']['command']]
        command.extend(user['exec']['args'])
        output = subprocess.check_output(command)
        c = json.loads(output.decode('utf-8'))
        user['token'] = c['status']['token']
        del user['exec']

        loader = KubeConfigLoader(config)
        config = type.__call__(Configuration)
        loader.load_and_set(config)
        Configuration.set_default(config)


class Status(Enum):
    provided = 0
    not_exist = 1
    creating = 2
    created = 3
    failed = 4
    deleting = 5
    deleted = 6

    def __str__(self):
        return ' '.join(self.name.split('_'))


class ResourceReporter:
    def __init__(self):
        self.spinner = Halo(text='', spinner='dots')

    def progress(self, resource):
        self.spinner.start(text='[ {0: <10}] {1}'.format(resource.status, resource.description))

    def succeed(self, resource):
        self.spinner.succeed(
            text='[ {0: <10}] {1} [{2}].'.format(resource.status, resource.description, resource.resource_id))

    def fail(self, resource):
        self.spinner.fail(text='[ {0: <10}] {1}'.format(resource.status, resource.description))

    def warn(self, text):
        self.spinner.warn(text=text)

    def info(self, resource):
        self.spinner.info(text='[ {} ] {} [{}].'.format(resource.status, resource.description, resource.resource_id))

    def report_stack_creation(self, name, resources, stack_id):
        cf = boto3.session.Session().resource('cloudformation')
        stack = cf.Stack(stack_id)
        rmap = {r.name: r for r in resources}
        completed = set()
        for r in resources:
            if r.status == Status.provided or r.status == Status.created:
                self.succeed(r)
                completed.add(r.name)

        current = None
        while stack.stack_status in ['CREATE_IN_PROGRESS', 'ROLLBACK_IN_PROGRESS']:
            states = {rs.logical_resource_id: rs for rs in stack.resource_summaries.all()}
            if current:
                rs = states.get(current)
                r = rmap.get(current)
                if rs.resource_status in ['CREATE_IN_PROGRESS']:
                    time.sleep(2)
                    continue
                else:
                    self.report_completed_resource(completed, r, rs, ['CREATE_COMPLETE'], Status.created)
                    current = None

            for name, rs in iteritems(states):
                r = rmap.get(name)
                if name not in completed and r:
                    if rs.resource_status in ['CREATE_IN_PROGRESS']:
                        current = name
                        r.status = Status.creating
                        self.progress(r)
                        break

                    self.report_completed_resource(completed, r, rs, ['CREATE_COMPLETE'], Status.created)
            time.sleep(2)
            stack = cf.Stack(stack_id)

        states = {rs.logical_resource_id: rs for rs in stack.resource_summaries.all()}
        if current:
            r = rmap.get(current)
            rs = states.get(current)
            self.report_completed_resource(completed, r, rs, ['CREATE_COMPLETE'], Status.created)

        for name, rs in iteritems(states):
            r = rmap.get(name)
            if name not in completed and r:
                self.report_completed_resource(completed, r, rs, ['CREATE_COMPLETE'], Status.created)

        if stack.stack_status in ['CREATE_FAILED', 'ROLLBACK_IN_PROGRESS', 'ROLLBACK_FAILED', 'ROLLBACK_COMPLETE']:
            raise EKSCliException('Failed to create EKS cluster {}: {}'.format(name, stack.stack_status))

        return stack

    def report_completed_resource(self, completed, resource, resource_summary, success_states, success):
        if resource_summary.resource_status in success_states:
            resource.status = success
            resource.resource_id = resource_summary.physical_resource_id
            self.succeed(resource)
        else:
            resource.status = Status.failed
            self.fail(resource)
        completed.add(resource.name)

    def report_stack_deletion(self, name, resources, stack_id):
        cf = boto3.session.Session().resource('cloudformation')
        stack = cf.Stack(stack_id)
        rmap = {r.name: r for r in resources}
        completed = set()
        for r in resources:
            if r.status == Status.not_exist or r.status == Status.deleted or r.status == Status.provided:
                self.succeed(r)
                completed.add(r.name)

        current = None
        while stack.stack_status not in ['DELETE_COMPLETE', 'DELETE_FAILED']:
            states = {rs.logical_resource_id: rs for rs in stack.resource_summaries.all()}
            if current:
                rs = states.get(current)
                r = rmap.get(current)
                if rs.resource_status in ['DELETE_IN_PROGRESS', 'CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                    time.sleep(2)
                    continue
                else:
                    self.report_completed_resource(completed, r, rs, ['DELETE_COMPLETE'], Status.deleted)
                    current = None

            for name, rs in iteritems(states):
                r = rmap.get(name)
                if name not in completed and r:
                    if rs.resource_status in ['DELETE_IN_PROGRESS', 'CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                        current = name
                        r.status = Status.deleting
                        self.progress(r)
                        break

                    self.report_completed_resource(completed, r, rs, ['DELETE_COMPLETE'], Status.deleted)
            time.sleep(2)
            stack = cf.Stack(stack_id)

        states = {rs.logical_resource_id: rs for rs in stack.resource_summaries.all()}
        if current:
            r = rmap.get(current)
            rs = states.get(current)
            self.report_completed_resource(completed, r, rs, ['DELETE_COMPLETE'], Status.deleted)

        for name, rs in iteritems(states):
            r = rmap.get(name)
            if name not in completed and r:
                self.report_completed_resource(completed, r, rs, ['DELETE_COMPLETE'], Status.deleted)

        if stack.stack_status in ['DELETE_FAILED']:
            raise EKSCliException('Failed to create EKS cluster {}: {}'.format(name, stack.stack_status))

        return


# https://stackoverflow.com/questions/37310718/mutually-exclusive-option-groups-in-python-click/
class MutuallyExclusiveOption(click.Option):
    mutex_groups = {}

    def __init__(self, *args, **kwargs):
        opts_list = kwargs.pop('mutex_group', '')
        self.mutex_group_key = ','.join(opts_list)
        self.mutex_groups[self.mutex_group_key] = 0
        help = kwargs.get('help', '')
        kwargs['help'] = help + (' NOTE: This argument may be one of: [{}].'.format(self.mutex_group_key))
        super(MutuallyExclusiveOption, self).__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        if self.name in self.mutex_group_key and self.name in opts:
            self.mutex_groups[self.mutex_group_key] += 1
        if self.mutex_groups[self.mutex_group_key] > 1:
            exclusive_against = self.mutex_group_key.split(',')
            exclusive_against.remove(self.name)
            raise click.UsageError("Illegal usage: `{}` is mutually exclusive against options {}.".format(
                self.name, exclusive_against))

        return super(MutuallyExclusiveOption, self).handle_parse_result(ctx, opts, args)
