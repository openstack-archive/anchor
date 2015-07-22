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

import sys
import textwrap
import unittest

from cryptography.hazmat.backends.openssl import backend
import mock

from anchor.X509 import errors as x509_errors
from anchor.X509 import name as x509_name
from anchor.X509 import signing_request


# find the class representing an open file; it depends on the python version
# it's used later for mocking
if sys.version_info[0] < 3:
    file_class = file  # noqa
else:
    import _io
    file_class = _io.TextIOWrapper


class TestX509Csr(unittest.TestCase):
    csr_data = textwrap.dedent("""
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

    def setUp(self):
        super(TestX509Csr, self).setUp()
        self.csr = signing_request.X509Csr()
        self.csr.from_buffer(TestX509Csr.csr_data)

    def tearDown(self):
        pass

    def test_get_pubkey_bits(self):
        # some OpenSSL gumph to test a reasonable attribute of the pubkey
        pubkey = self.csr.get_pubkey()
        size = backend._lib.EVP_PKEY_bits(pubkey)
        self.assertEqual(size, 384)

    def test_get_extensions(self):
        exts = self.csr.get_extensions()
        self.assertEqual(len(exts), 2)
        self.assertEqual(str(exts[0]), "basicConstraints CA:FALSE")
        self.assertEqual(str(exts[1]), ("keyUsage Digital Signature, Non "
                                        "Repudiation, Key Encipherment"))

    def test_read_from_file(self):
        open_name = 'anchor.X509.signing_request.open'
        with mock.patch(open_name, create=True) as mock_open:
            mock_open.return_value = mock.MagicMock(spec=file_class)
            m_file = mock_open.return_value.__enter__.return_value
            m_file.read.return_value = TestX509Csr.csr_data
            csr = signing_request.X509Csr()
            csr.from_file("some_path")

            name = csr.get_subject()
            entries = name.get_entries_by_nid(x509_name.NID_countryName)
            self.assertEqual(entries[0].get_value(), "UK")

    def test_bad_data_throws(self):
        bad_data = (
            "some bad data is "
            "EHRlc3RAYW5jaG9yLnRlc3QwTDANBgkqhkiG9w0BAQEFAAM7ADA4AjEA6m")

        csr = signing_request.X509Csr()
        self.assertRaises(x509_errors.X509Error,
                          csr.from_buffer,
                          bad_data)

    def test_get_subject_countryName(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_nid(x509_name.NID_countryName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "UK")

    def test_get_subject_stateOrProvinceName(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_nid(x509_name.NID_stateOrProvinceName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "stateOrProvinceName")
        self.assertEqual(entries[0].get_value(), "Narnia")

    def test_get_subject_localityName(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_nid(x509_name.NID_localityName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "localityName")
        self.assertEqual(entries[0].get_value(), "Funkytown")

    def test_get_subject_organizationName(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_nid(x509_name.NID_organizationName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationName")
        self.assertEqual(entries[0].get_value(), "Anchor Testing")

    def test_get_subject_organizationUnitName(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_nid(x509_name.NID_organizationalUnitName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationalUnitName")
        self.assertEqual(entries[0].get_value(), "testing")

    def test_get_subject_commonName(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_nid(x509_name.NID_commonName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "commonName")
        self.assertEqual(entries[0].get_value(), "anchor.test")

    def test_get_subject_emailAddress(self):
        name = self.csr.get_subject()
        entries = name.get_entries_by_nid(x509_name.NID_pkcs9_emailAddress)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "emailAddress")
        self.assertEqual(entries[0].get_value(), "test@anchor.test")
