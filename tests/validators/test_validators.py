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

import netaddr

import unittest

from anchor import validators
from anchor.X509 import signing_request


class TestValidators(unittest.TestCase):
    #CSR: CN=ossg.test.com/emailAddress=openstack-security@lists.openstack.org
    csr_data = (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIIDBTCCAe0CAQAwgb8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh\n"
        "MRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMSEwHwYDVQQKExhPcGVuU3RhY2sgU2Vj\n"
        "dXJpdHkgR3JvdXAxETAPBgNVBAsTCFNlY3VyaXR5MRYwFAYDVQQDEw1vc3NnLnRl\n"
        "c3QuY29tMTUwMwYJKoZIhvcNAQkBFiZvcGVuc3RhY2stc2VjdXJpdHlAbGlzdHMu\n"
        "b3BlbnN0YWNrLm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJCw\n"
        "hIh3kwHGrGff7bHpY0x7ebXS8CfnwDx/wFSqlBeARL9f4riN172P4hkk7F+QQ2R9\n"
        "88osQX4dmbQZDX18y85TTQv9jmtzvTZtJM2UQ80XMIVLZjpK5966cmJKqn/s+IaL\n"
        "zh+kqyb7S6xV0590VarEFZ6JsXdxU9TtVHOWCfn/P8swr5DCTzsE/LUIuVdqgkGh\n"
        "g63E9iLYtAOUcQv6lpmrI8NHOMK2F7XnP64IEshpZ4POzc7m8nTEHHb0+xxxiive\n"
        "mwLTp6pyZ5wBx/Dvk2Dc7SF6x51wOxAxdWc3vxwA5Q2nbFK2RlBHCiIi+ZK3i5S/\n"
        "tOkcQydQ0Cl9escDrv0CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQA1dpxxTGFF\n"
        "TGFenVJlT2uecvXK4UePeaslRx2P1k3xwJK9ZEvKY297cqhK5Y8kWyzNUjGFLHPr\n"
        "RlgjFMYlUICNgCdcWD2b0avZ9q648+F3b9CWKg0kNMhxyQpXdSeLZOzpDVUyr6TN\n"
        "GcCZqcQQclixruXsIGQoZFIXazGju2UTtxwK/J87u2S0yR2bR48dPlNXAWKV+e4o\n"
        "Ua0RaDUUBypZNMMbY6KSB6C7oXGzA/WOnvNz9PzhXlqgWhOv5M6iG3sYDtKllXJT\n"
        "7lcLhUzNVdWaPveTqX/V8QX//53IkyNa+IBm+H84UE5M0GFunqFBYqrWw8S46tMQ\n"
        "JQxgjf65ujnn\n"
        "-----END CERTIFICATE REQUEST-----\n")

    def setUp(self):
        super(TestValidators, self).setUp()
        self.csr = signing_request.X509Csr()
        self.csr.from_buffer(TestValidators.csr_data)

    def tearDown(self):
        super(TestValidators, self).tearDown()

    def test_csr_get_cn(self):
        name = validators.csr_get_cn(self.csr)
        self.assertEqual(name, "ossg.test.com")

    def test_check_domains(self):
        test_domain = 'ossg.test.com'
        test_allowed = ['.example.com', '.test.com']

        self.assertTrue(validators.check_domains(test_domain, test_allowed))
        self.assertFalse(validators.check_domains('gmail.com', test_allowed))

    @unittest.skip("This test works but the code it tests is broken, I think. (hyakuhei)")
    def test_check_networks(self):
        bad_domain = 'x.![].y.*%'
        allowed_networks = ['127/8']
        self.assertFalse(
            validators.check_networks,
            bad_domain,
            allowed_networks)

        self.assertTrue(
            validators.check_networks,
            'localhost',
            allowed_networks
        )

        self.assertFalse(
            validators.check_networks,
            'example.com',
            allowed_networks
        )
