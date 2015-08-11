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

import io
import textwrap
import unittest

import mock
from pyasn1_modules import rfc2459

from anchor.X509 import errors as x509_errors
from anchor.X509 import extension
from anchor.X509 import name as x509_name
from anchor.X509 import signing_request
from anchor.X509 import utils


class TestX509Csr(unittest.TestCase):
    csr_data = textwrap.dedent(u"""
        -----BEGIN CERTIFICATE REQUEST-----
        MIIBWTCCARMCAQAwgZQxCzAJBgNVBAYTAlVLMQ8wDQYDVQQIEwZOYXJuaWExEjAQ
        BgNVBAcTCUZ1bmt5dG93bjEXMBUGA1UEChMOQW5jaG9yIFRlc3RpbmcxEDAOBgNV
        BAsTB3Rlc3RpbmcxFDASBgNVBAMTC2FuY2hvci50ZXN0MR8wHQYJKoZIhvcNAQkB
        FhB0ZXN0QGFuY2hvci50ZXN0MEwwDQYJKoZIhvcNAQEBBQADOwAwOAIxAOpvxkCx
        NNTc86GVnP4rWvaniOnHaemXbhBOoFxhMwaghiq7u5V9ZKkUZfbu+L+ZSQIDAQAB
        oCkwJwYJKoZIhvcNAQkOMRowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DANBgkq
        hkiG9w0BAQUFAAMxALaK8/HR73ZSvHiWo7Mduin0S519aJBm+gO8d9iliUkK00gQ
        VMs9DuTAxljX7t7Eug==
        -----END CERTIFICATE REQUEST-----""")

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

    def setUp(self):
        super(TestX509Csr, self).setUp()
        self.csr = signing_request.X509Csr.from_buffer(TestX509Csr.csr_data)

    def tearDown(self):
        pass

    def test_get_pubkey(self):
        pubkey = self.csr.get_pubkey()
        self.assertEqual(pubkey['algorithm']['algorithm'],
                         rfc2459.rsaEncryption)

    def test_get_extensions(self):
        exts = self.csr.get_extensions()
        self.assertEqual(len(exts), 2)
        self.assertFalse(exts[0].get_ca())
        self.assertIsNone(exts[0].get_path_len_constraint())
        self.assertTrue(exts[1].get_usage('digitalSignature'))
        self.assertTrue(exts[1].get_usage('nonRepudiation'))
        self.assertTrue(exts[1].get_usage('keyEncipherment'))
        self.assertFalse(exts[1].get_usage('cRLSign'))

    def test_add_extension(self):
        csr = signing_request.X509Csr()
        bc = extension.X509ExtensionBasicConstraints()
        csr.add_extension(bc)
        self.assertEqual(1, len(csr.get_extensions()))
        csr.add_extension(bc)
        self.assertEqual(2, len(csr.get_extensions()))

    def test_add_extension_invalid_type(self):
        csr = signing_request.X509Csr()
        with self.assertRaises(x509_errors.X509Error):
            csr.add_extension(1234)

    def test_read_from_file(self):
        open_name = 'anchor.X509.signing_request.open'
        f = io.StringIO(TestX509Csr.csr_data)
        with mock.patch(open_name, create=True) as mock_open:
            mock_open.return_value = f
            csr = signing_request.X509Csr.from_file("some_path")

            name = csr.get_subject()
            entries = name.get_entries_by_oid(x509_name.OID_countryName)
            self.assertEqual(entries[0].get_value(), "UK")

    def test_bad_data_throws(self):
        bad_data = (
            u"some bad data is "
            "EHRlc3RAYW5jaG9yLnRlc3QwTDANBgkqhkiG9w0BAQEFAAM7ADA4AjEA6m")

        csr = signing_request.X509Csr()
        self.assertRaises(x509_errors.X509Error,
                          csr.from_buffer,
                          bad_data)

    def test_get_subject_countryName(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_countryName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "UK")

    def test_get_subject_stateOrProvinceName(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_stateOrProvinceName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "stateOrProvinceName")
        self.assertEqual(entries[0].get_value(), "Narnia")

    def test_get_subject_localityName(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_localityName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "localityName")
        self.assertEqual(entries[0].get_value(), "Funkytown")

    def test_get_subject_organizationName(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_organizationName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationName")
        self.assertEqual(entries[0].get_value(), "Anchor Testing")

    def test_get_subject_organizationUnitName(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_organizationalUnitName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationalUnitName")
        self.assertEqual(entries[0].get_value(), "testing")

    def test_get_subject_commonName(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_commonName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "commonName")
        self.assertEqual(entries[0].get_value(), "anchor.test")

    def test_get_subject_emailAddress(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_pkcs9_emailAddress)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "emailAddress")
        self.assertEqual(entries[0].get_value(), "test@anchor.test")

    def test_sign(self):
        key = utils.get_private_key_from_pem(self.key_rsa_data)
        self.csr.sign(key)
        # 10 bytes is definitely enough for non malicious case, right?
        self.assertEqual(b'5I\xc2\x03\x97\xd2\xf0\xd6\x06\x8c',
                         self.csr._get_signature()[:10])

    def test_verify(self):
        self.assertTrue(self.csr.verify())
