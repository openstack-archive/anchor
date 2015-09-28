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

import textwrap
import unittest

import netaddr

from anchor import validators
from anchor.X509 import signing_request


class TestBaseValidators(unittest.TestCase):
    csr_data_with_cn = textwrap.dedent(u"""
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
        C=US, ST=California, L=San Francisco,
        O=OpenStack Security Group, OU=Security,
        CN=ossg.test.com/emailAddress=openstack-security@lists.openstack.org
    """

    csr_data_without_cn = textwrap.dedent(u"""
        -----BEGIN CERTIFICATE REQUEST-----
        MIIC7TCCAdUCAQAwgacxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlh
        MRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMSEwHwYDVQQKDBhPcGVuU3RhY2sgU2Vj
        dXJpdHkgR3JvdXAxETAPBgNVBAsMCFNlY3VyaXR5MTUwMwYJKoZIhvcNAQkBFiZv
        cGVuc3RhY2stc2VjdXJpdHlAbGlzdHMub3BlbnN0YWNrLm9yZzCCASIwDQYJKoZI
        hvcNAQEBBQADggEPADCCAQoCggEBAMy2NIPIkpUt3bIFWINacX1piE1aqnQwy0MW
        dpEJYnZKECJI9UTdIXWXKuKX2+c4igSvPThf/9RBPjXWflYEh67CEcgFwrb4B3mr
        GtwAz/os19Tp7uiCZ2WHwh1ed8HuFGs4Iwtka4f18s03SYe+r7p0KwFsJYT9wgMK
        7TvM/ZRZwHMnhDinlT7II6AKyLoU8y7EAe7Z75RMHKVaUiMwqD7vJJ6WEwS9GcGL
        9CVWNBuyaVAchwqN4ejpMBPwAiSo3O7n3XM0oufhrtI6gz1V3l3PiIbDX+eb+Rit
        Fc3RvmlQ0DApweREUBEfTA1NVls4qvuRdg5ps6+uwI6WqQlEvwsCAwEAAaAAMA0G
        CSqGSIb3DQEBCwUAA4IBAQBfasOCSFjEHVazOeiJuaQnfRtwmEK0rDQsUL5oy21h
        YbX5RyKLavDlU2er2N3NIEoZ+xBODEmXpKg0QXR3rGLvR/utPvjAU03a56ryw+mY
        DlyBvC15oqnhdjlq9UvdhKXu9kpaQksNbn63PKoVSIPHj2wEs1qnneYTEWQngGP1
        bcoRVE4esRNDBwo1SVC1y5QMjd/Ta4b9jeRU/3jOSuJHVUA+xaWhdRj9VX6EgvxY
        x2LlF2bajZ8HdOb0MS+zvTQjyySXd1qg1D9APJRfNOxlIxOZdPTjH5+HT8fRfXGC
        QxrcV4H0CsWt61dgiLe6w7CERmR7liD+yFoZYiTTXcbT
        -----END CERTIFICATE REQUEST-----""")

    """
    Subject:
        C=US, ST=California, L=San Francisco, O=OpenStack Security Group,
        OU=Security/emailAddress=openstack-security@lists.openstack.org
    """

    def setUp(self):
        super(TestBaseValidators, self).setUp()
        self.csr = signing_request.X509Csr.from_buffer(
            TestBaseValidators.csr_data_with_cn)

    def tearDown(self):
        super(TestBaseValidators, self).tearDown()

    def test_csr_require_cn(self):
        name = validators.csr_require_cn(self.csr)
        self.assertEqual(name, "ossg.test.com")

        self.csr = signing_request.X509Csr.from_buffer(
            TestBaseValidators.csr_data_without_cn)
        with self.assertRaises(validators.ValidationError):
            validators.csr_require_cn(self.csr)

    def test_check_domains(self):
        test_domain = 'good.example.com'
        test_allowed = ['.example.com', '.example.net']
        self.assertTrue(validators.check_domains(test_domain, test_allowed))
        self.assertFalse(validators.check_domains('bad.example.org',
                                                  test_allowed))

    def test_check_networks(self):
        good_ip = netaddr.IPAddress('10.2.3.4')
        bad_ip = netaddr.IPAddress('88.2.3.4')
        test_allowed = ['10/8']
        self.assertTrue(validators.check_networks(good_ip, test_allowed))
        self.assertFalse(validators.check_networks(bad_ip, test_allowed))

    def test_check_networks_invalid(self):
        with self.assertRaises(TypeError):
            validators.check_networks('1.2.3.4', ['10/8'])

    def test_check_networks_passthrough(self):
        good_ip = netaddr.IPAddress('10.2.3.4')
        self.assertTrue(validators.check_networks(good_ip, []))
