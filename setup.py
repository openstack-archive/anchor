#!/usr/bin/env python

from setuptools import setup

setup(
    name="anchor",
    description="webservice to auto-sign certificates for short amount of time",
    version="1.0.0",
    packages=['anchor'],
    include_package_data=True,
    install_requires=[
        'm2crypto',
        'pecan',
        'paste',
        'setuptools>=1.0',
        'netaddr',
    ],
    extras_require={
        'auth_ldap': ['python-ldap'],
        'auth_keystone': ['requests'],
        'develop': ['watchdog'],
        'production': ['uwsgi'],
    },
    setup_requires=[
        'setuptools>=1.0',
    ],
    zip_safe=False
)
