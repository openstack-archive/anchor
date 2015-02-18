# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import unittest
from anchor.app import ConfigValidationException

class TestValidDN(unittest.TestCase):
    test_validator = [
        {
            "name": "default",
            "steps": [
                ('common_name', {'allowed_domains': ['.example.com']}),
                ('alternative_names', {'allowed_domains': ['.example.com']}),
                ('server_group', {'group_prefixes': {
                    'nv': 'Nova_Team',
                    'sw': 'Swift_Team',
                    'bk': 'Bock_Team',
                    'gl': 'Glance_Team',
                    'cs': 'CS_Team',
                    'mb': 'MB_Team',
                    'ops': 'SysEng_Team',
                    'qu': 'Neutron_Team',
                    }}),
                ('extensions', {'allowed_extensions': ['keyUsage', 'subjectAltName', 'basicConstraints', 'subjectKeyIdentifier']}),
                ('key_usage', {'allowed_usage': ['Digital Signature', 'Key Encipherment', 'Non Repudiation', 'Certificate Sign', 'CRL Sign']}),
                ('ca_status', {'ca_requested': False}),
                ('source_cidrs', {'cidrs': ["127.0.0.0/8"]}),
            ]
        },
        {
            "name": "ip",
            "steps": [
                ('common_name', {'allowed_networks': ['127/8']}),
                ('alternative_names', {'allowed_networks': ['127/8']}),
                ('ca_status', {'ca_requested': False}),
                ('source_cidrs', {'cidrs': ["127.0.0.0/8"]}),
            ]
        },
    ]


    def setUp(self):
        super(TestValidDN, self).setUp()
        # self.domain_list = domains

    def tearDown(self):
        pass

    def test_testing(self):
        self.assertTrue(True)

    def test_validate_config(self):
        self.assertRaises(ConfigValidationException, validate_config, TestValidDN.test_validator)

