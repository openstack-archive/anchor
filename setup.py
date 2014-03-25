#!/usr/bin/env python

from setuptools import setup

setup(
    name="ephemeral_ca",
    description="webservice to auto-sign certificates for short amount of time",
    version="0.1",
    packages=['ephemeral_ca'],
    install_requires=[
        'm2crypto',
        'flask',
        'flask-ldap',
        'setuptools>=1.0',
    ],
    setup_requires=[
        'setuptools>=1.0',
    ],
    zip_safe=False,
    entry_points={
        'console_scripts': ['ephemeral_ca_server=ephemeral_ca:run_server'],
    }
)
