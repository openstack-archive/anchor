# -*- coding:utf-8 -*-
#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
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

from pyasn1.type import univ as asn1_univ

from anchor import certificate_ops
from anchor.X509 import certificate
from anchor.X509 import extension
from anchor.X509 import signing_request
import tests


class UnknownExtension(extension.X509Extension):
    _oid = asn1_univ.ObjectIdentifier("1.2.3.4")
    spec = asn1_univ.Null


class SigningBackendExtensions(tests.DefaultConfigMixin,
                               tests.DefaultRequestMixin, unittest.TestCase):
    def test_copy_good_extensions(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_sample_bytes)
        ext = extension.X509ExtensionSubjectAltName()
        ext.add_dns_id("example.com")
        csr.add_extension(ext)

        pem = certificate_ops.sign(csr, self.sample_conf_ca['default_ca'])
        cert = certificate.X509Certificate.from_buffer(pem)
        self.assertEqual(1, len(cert.get_extensions(
            extension.X509ExtensionSubjectAltName)))

    def test_ignore_unknown_extensions(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_sample_bytes)
        ext = UnknownExtension()
        csr.add_extension(ext)

        pem = certificate_ops.sign(csr, self.sample_conf_ca['default_ca'])
        cert = certificate.X509Certificate.from_buffer(pem)
        self.assertEqual(0, len(cert.get_extensions(UnknownExtension)))

    def test_fail_critical_unknown_extensions(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_sample_bytes)
        ext = UnknownExtension()
        ext.set_critical(True)
        csr.add_extension(ext)

        with self.assertRaises(certificate_ops.SigningError):
            certificate_ops.sign(csr, self.sample_conf_ca['default_ca'])
