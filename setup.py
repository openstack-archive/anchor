#!/usr/bin/env python

from setuptools import setup

setup(
    name="ephemeral_ca",
    description="webservice to auto-sign certificates for short amount of time",
    version="0.1",
    packages=['ephemeral_ca'],
    include_package_data=True,
    install_requires=[
        'm2crypto',
        'pecan',
        'setuptools>=1.0',
    ],
    extras_require={
        'auth_ldap': ['python-ldap'],
        'auth_keystone': ['requests'],
        'develop': ['watchdog'],
    },
    setup_requires=[
        'setuptools>=1.0',
    ],
    zip_safe=False
)
