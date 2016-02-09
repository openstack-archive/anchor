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

import textwrap
import unittest

from pyasn1.type import univ as asn1_univ

from anchor import signers
from anchor.signers import cryptography_io
from anchor.X509 import certificate
from anchor.X509 import extension
from anchor.X509 import signing_request
from anchor.X509 import utils
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

        pem = signers.sign_generic(csr, self.sample_conf_ca['default_ca'],
                                   'RSA', lambda x: b"")
        cert = certificate.X509Certificate.from_buffer(pem)
        self.assertEqual(1, len(cert.get_extensions(
            extension.X509ExtensionSubjectAltName)))

    def test_ignore_unknown_extensions(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_sample_bytes)
        ext = UnknownExtension()
        csr.add_extension(ext)

        pem = signers.sign_generic(csr, self.sample_conf_ca['default_ca'],
                                   'RSA', lambda x: b"")
        cert = certificate.X509Certificate.from_buffer(pem)
        self.assertEqual(2, len(cert.get_extensions()))

    def test_fail_critical_unknown_extensions(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_sample_bytes)
        ext = UnknownExtension()
        ext.set_critical(True)
        csr.add_extension(ext)

        with self.assertRaises(signers.SigningError):
            signers.sign_generic(csr, self.sample_conf_ca['default_ca'],
                                 'RSA', lambda x: b"")


class TestCryptographyBackend(tests.DefaultConfigMixin,
                              tests.DefaultRequestMixin, unittest.TestCase):
    key_rsa_data = textwrap.dedent("""
        -----BEGIN RSA PRIVATE KEY-----
        MIICXAIBAAKBgQCeeqg1Qeccv8hqj1BP9KEJX5QsFCxR62M8plPb5t4sLo8UYfZd
        6kFLcOP8xzwwvx/eFY6Sux52enQ197o8aMwyP77hMhZqtd8NCgLJMVlUbRhwLti0
        SkHFPic0wAg+esfXa6yhd5TxC+bti7MgV/ljA80XQxHH8xOjdOoGN0DHfQIDAQAB
        AoGBAJ2ozJpe+7qgGJPaCz3f0izvBwtq7kR49fqqRZbo8HHnx7OxWVVI7LhOkKEy
        2/Bq0xsvOu1CdiXL4LynvIDIiQqLaeINzG48Rbk+0HadbXblt3nDkIWdYII6zHKI
        W9ewX4KpHEPbrlEO9BjAlAcYsDIvFIMYpQhtQ+0R/gmZ99WJAkEAz5C2a6FIcMbE
        o3aTc9ECq99zY7lxh+6aLpUdIeeHyb/QzfGDBdlbpBAkA6EcxSqp0aqH4xIQnYHa
        3P5ZCShqSwJBAMN1sb76xq94xkg2cxShPFPAE6xKRFyKqLgsBYVtulOdfOtOnjh9
        1SK2XQQfBRIRdG4Q/gDoCP8XQHpJcWMk+FcCQDnuJqulaOVo5GrG5mJ1nCxCAh98
        G06X7lo/7dCPoRtSuMExvaK9RlFk29hTeAcjYCAPWzupyA9dtarmJg1jRT8CQCKf
        gYnb8D/6+9yk0IPR/9ayCooVacCeyz48hgnZowzWs98WwQ4utAd/GED3obVOpDov
        Bl9wus889i3zPoOac+cCQCZHredQcJGd4dlthbVtP2NhuPXz33JuETGR9pXtsDUZ
        uX/nSq1oo9kUh/dPOz6aP5Ues1YVe3LExmExPBQfwIE=
        -----END RSA PRIVATE KEY-----""").encode('ascii')

    def test_sign_bad_md(self):
        key = utils.get_private_key_from_pem(self.key_rsa_data)
        with self.assertRaises(signers.SigningError):
            cryptography_io.make_signer(key, "BAD", "RSA")

    def test_sign_bad_key(self):
        with self.assertRaises(signers.SigningError):
            cryptography_io.make_signer("BAD", "sha256", "RSA")
