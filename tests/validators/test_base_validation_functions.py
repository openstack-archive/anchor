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

import socket
import textwrap
import unittest

import mock

from anchor import validators
from anchor.X509 import signing_request


class TestBaseValidators(unittest.TestCase):
    csr_data = textwrap.dedent("""
        -----BEGIN CERTIFICATE REQUEST-----
        MIIDBTCCAe0CAQAwgb8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
        MRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMSEwHwYDVQQKExhPcGVuU3RhY2sgU2Vj
        dXJpdHkgR3JvdXAxETAPBgNVBAsTCFNlY3VyaXR5MRYwFAYDVQQDEw1vc3NnLnRl
        c3QuY29tMTUwMwYJKoZIhvcNAQkBFiZvcGVuc3RhY2stc2VjdXJpdHlAbGlzdHMu
        b3BlbnN0YWNrLm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJCw
        hIh3kwHGrGff7bHpY0x7ebXS8CfnwDx/wFSqlBeARL9f4riN172P4hkk7F+QQ2R9
        88osQX4dmbQZDX18y85TTQv9jmtzvTZtJM2UQ80XMIVLZjpK5966cmJKqn/s+IaL
        zh+kqyb7S6xV0590VarEFZ6JsXdxU9TtVHOWCfn/P8swr5DCTzsE/LUIuVdqgkGh
        g63E9iLYtAOUcQv6lpmrI8NHOMK2F7XnP64IEshpZ4POzc7m8nTEHHb0+xxxiive
        mwLTp6pyZ5wBx/Dvk2Dc7SF6x51wOxAxdWc3vxwA5Q2nbFK2RlBHCiIi+ZK3i5S/
        tOkcQydQ0Cl9escDrv0CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQA1dpxxTGFF
        TGFenVJlT2uecvXK4UePeaslRx2P1k3xwJK9ZEvKY297cqhK5Y8kWyzNUjGFLHPr
        RlgjFMYlUICNgCdcWD2b0avZ9q648+F3b9CWKg0kNMhxyQpXdSeLZOzpDVUyr6TN
        GcCZqcQQclixruXsIGQoZFIXazGju2UTtxwK/J87u2S0yR2bR48dPlNXAWKV+e4o
        Ua0RaDUUBypZNMMbY6KSB6C7oXGzA/WOnvNz9PzhXlqgWhOv5M6iG3sYDtKllXJT
        7lcLhUzNVdWaPveTqX/V8QX//53IkyNa+IBm+H84UE5M0GFunqFBYqrWw8S46tMQ
        JQxgjf65ujnn
        -----END CERTIFICATE REQUEST-----""")
    """
    Subject:
        CN=ossg.test.com/emailAddress=openstack-security@lists.openstack.org
    """

    def setUp(self):
        super(TestBaseValidators, self).setUp()
        self.csr = signing_request.X509Csr()
        self.csr.from_buffer(TestBaseValidators.csr_data)

    def tearDown(self):
        super(TestBaseValidators, self).tearDown()

    def test_csr_get_cn(self):
        name = validators.csr_get_cn(self.csr)
        self.assertEqual(name, "ossg.test.com")

    def test_check_domains(self):
        test_domain = 'ossg.test.com'
        test_allowed = ['.example.com', '.test.com']
        self.assertTrue(validators.check_domains(test_domain, test_allowed))
        self.assertFalse(validators.check_domains('gmail.com', test_allowed))

    def test_check_networks_bad_domain(self):
        bad_domain = 'bad!$domain'
        allowed_networks = ['127/8', '10/8']
        self.assertFalse(validators.check_networks(
            bad_domain, allowed_networks))

    @mock.patch('socket.gethostbyname_ex')
    def test_check_networks_both(self, gethostbyname_ex):
        allowed_networks = ['15/8', '74.125/16']
        gethostbyname_ex.return_value = (
            'example.com',
            [],
            [
                '74.125.224.64',
                '74.125.224.67',
                '74.125.224.68',
                '74.125.224.70',
            ]
        )
        self.assertTrue(validators.check_networks(
            'example.com', allowed_networks))
        self.assertTrue(validators.check_networks_strict(
            'example.com', allowed_networks))

        gethostbyname_ex.return_value = ('example.com', [], ['12.2.2.2'])
        self.assertFalse(validators.check_networks(
            'example.com', allowed_networks))

        gethostbyname_ex.return_value = (
            'example.com',
            [],
            [
                '15.8.2.2',
                '15.8.2.1',
                '16.1.1.1',
            ]
        )
        self.assertFalse(validators.check_networks_strict(
            'example.com', allowed_networks))

    @mock.patch('socket.gethostbyname_ex')
    def test_check_networks_exception(self, gethostbyname_ex):
        gethostbyname_ex.side_effect = socket.gaierror()
        self.assertFalse(
            validators.check_networks('mock', ['mock']),
        )

    @mock.patch('socket.gethostbyname_ex')
    def test_check_networks_strict_exception(self, gethostbyname_ex):
        gethostbyname_ex.side_effect = socket.gaierror()
        self.assertFalse(
            validators.check_networks_strict('mock', ['mock']),
        )
