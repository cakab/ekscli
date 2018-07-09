#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

import ekscli

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = ['click>=6.0',
                'future>=0.16.0',
                'troposphere>=2.3.1',
                'awacs>=0.7.2',
                'boto3>=1.7.37',
                'halo>=0.0.12',
                'kubernetes>=6.0.0',
                'oyaml>=0.4',
                'jinja2>=2.10',
                'netaddr>=0.7.19',
                'tabulate>=0.8.2'
                ]

setup_requirements = ['pytest-runner', ]

test_requirements = ['pytest', ]

setup(
    author=ekscli.__author__,
    author_email=ekscli.__email__,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    description="A simple and flexible commandline tool for AWS EKS management",
    install_requires=requirements,
    license="MIT license",
    long_description=readme,
    include_package_data=True,
    keywords='ekscli',
    name='ekscli',
    packages=find_packages(exclude=['tests']),
    entry_points={'console_scripts': [
        'eks = ekscli.cli:cli'
    ]},
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/cakab/ekscli',
    version=ekscli.__version__,
    zip_safe=False,
)
