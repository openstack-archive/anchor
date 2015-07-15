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

import mock
import webob

from anchor import certificate_ops
from anchor import fixups
from anchor import jsonloader
from anchor.X509 import signing_request


class TestFixupFunctionality(unittest.TestCase):
    csr_data_with_cn = textwrap.dedent("""
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
    def setUp(self):
        super(TestFixupFunctionality, self).setUp()
        self.csr = signing_request.X509Csr()
        self.csr.from_buffer(TestFixupFunctionality.csr_data_with_cn)

    def test_with_noop(self):
        """Ensure single fixup is processed."""

        config = "anchor.jsonloader.conf._config"
        data = {'fixups': {'noop': {}}}

        with mock.patch.object(fixups, "noop") as mock_noop:
            mock_noop.return_value = self.csr
            with mock.patch.dict(config, data):
                certificate_ops.fixup_csr(self.csr, None)

            mock_noop.assert_called_with(csr=self.csr, conf=jsonloader.conf,
                                         request=None)

    def test_with_no_fixups(self):
        """Ensure no fixups is ok."""

        config = "anchor.jsonloader.conf._config"
        data = {'fixups': {}}

        with mock.patch.dict(config, data):
            certificate_ops.fixup_csr(self.csr, None)

    def test_with_broken_fixup(self):
        """Ensure broken fixups stop processing."""

        config = "anchor.jsonloader.conf._config"
        data = {'fixups': {'noop': {}}}

        with mock.patch.object(fixups, "noop") as mock_noop:
            mock_noop.side_effect = Exception("BOOM")
            with mock.patch.dict(config, data):
                with self.assertRaises(webob.exc.HTTPServerError):
                    certificate_ops.fixup_csr(self.csr, None)
