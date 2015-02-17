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

from anchor.X509 import certificate
from anchor.X509 import errors as x509_errors
from anchor.X509 import name as x509_name


class TestX509Cert(unittest.TestCase):
    cert_data = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIICKjCCAZOgAwIBAgIIfeW6dwGe6wMwDQYJKoZIhvcNAQEFBQAwUjELMAkGA1UE\n"
        "BhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxFjAUBgNVBAoTDUhlcnAgRGVycCBw\n"
        "bGMxFjAUBgNVBAMTDWhlcnAuZGVycC5wbGMwHhcNMTUwMTE0MTQxMDE5WhcNMTUw\n"
        "MTE1MTQxMDE5WjCBlDELMAkGA1UEBhMCVUsxDzANBgNVBAgTBk5hcm5pYTESMBAG\n"
        "A1UEBxMJRnVua3l0b3duMRcwFQYDVQQKEw5BbmNob3IgVGVzdGluZzEQMA4GA1UE\n"
        "CxMHdGVzdGluZzEUMBIGA1UEAxMLYW5jaG9yLnRlc3QxHzAdBgkqhkiG9w0BCQEW\n"
        "EHRlc3RAYW5jaG9yLnRlc3QwTDANBgkqhkiG9w0BAQEFAAM7ADA4AjEA6m/GQLE0\n"
        "1NzzoZWc/ita9qeI6cdp6ZduEE6gXGEzBqCGKru7lX1kqRRl9u74v5lJAgMBAAGj\n"
        "GjAYMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMA0GCSqGSIb3DQEBBQUAA4GBAGeX\n"
        "hSul19/DgwM5m3cj6y9+dkOhXCdImG1O6wjDHxa/xU+hlPJwGZr5zrcBsk/8jaIP\n"
        "z1FWAhsmZBl0zSJY7XEZ9jmw7JIaCy3XpYMVEA2LGEofydr7N3CRqIE5ehdAh5rz\n"
        "gTLni27WuVJFVBNoTU1JfoxBSm/RBLdTj92g9N5g\n"
        "-----END CERTIFICATE-----\n")

    def setUp(self):
        super(TestX509Cert, self).setUp()
        self.cert = certificate.X509Certificate()
        self.cert.from_buffer(TestX509Cert.cert_data)

    def tearDown(self):
        pass

    def test_bad_data_throws(self):
        bad_data = (
            "some bad data is "
            "EHRlc3RAYW5jaG9yLnRlc3QwTDANBgkqhkiG9w0BAQEFAAM7ADA4AjEA6m")

        cert = certificate.X509Certificate()
        self.assertRaises(x509_errors.X509Error,
                          cert.from_buffer,
                          bad_data)

    def test_get_bad_elem(self):
        name = self.cert.get_subject()
        self.assertRaises(x509_errors.X509Error,
                          name.get_entries_by_nid_name,
                          'BAD')

    def test_get_subject_c(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('C')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "UK")

    def test_get_subject_countryName(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('countryName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "UK")

    def test_get_subject_st(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('ST')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "stateOrProvinceName")
        self.assertEqual(entries[0].get_value(), "Narnia")

    def test_get_subject_sp(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('SP')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "stateOrProvinceName")
        self.assertEqual(entries[0].get_value(), "Narnia")

    def test_get_subject_stateOrProvinceName(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('stateOrProvinceName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "stateOrProvinceName")
        self.assertEqual(entries[0].get_value(), "Narnia")

    def test_get_subject_l(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('L')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "localityName")
        self.assertEqual(entries[0].get_value(), "Funkytown")

    def test_get_subject_localityName(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('localityName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "localityName")
        self.assertEqual(entries[0].get_value(), "Funkytown")

    def test_get_subject_o(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('O')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationName")
        self.assertEqual(entries[0].get_value(), "Anchor Testing")

    def test_get_subject_organizationName(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('organizationName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationName")
        self.assertEqual(entries[0].get_value(), "Anchor Testing")

    def test_get_subject_ou(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('OU')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationalUnitName")
        self.assertEqual(entries[0].get_value(), "testing")

    def test_get_subject_organizationUnitName(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('organizationalUnitName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationalUnitName")
        self.assertEqual(entries[0].get_value(), "testing")

    def test_get_subject_cn(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('CN')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "commonName")
        self.assertEqual(entries[0].get_value(), "anchor.test")

    def test_get_subject_commonName(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('commonName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "commonName")
        self.assertEqual(entries[0].get_value(), "anchor.test")

    def test_get_subject_email(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('Email')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "emailAddress")
        self.assertEqual(entries[0].get_value(), "test@anchor.test")

    def test_get_subject_emailAddress(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('Email')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "emailAddress")
        self.assertEqual(entries[0].get_value(), "test@anchor.test")

    def test_get_issuer_c(self):
        name = self.cert.get_issuer()
        entries = name.get_entries_by_nid_name('C')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "AU")

    def test_get_issuer_countryName(self):
        name = self.cert.get_issuer()
        entries = name.get_entries_by_nid_name('countryName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "AU")

    def test_get_issuer_st(self):
        name = self.cert.get_issuer()
        entries = name.get_entries_by_nid_name('ST')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "stateOrProvinceName")
        self.assertEqual(entries[0].get_value(), "Some-State")

    def test_get_issuer_o(self):
        name = self.cert.get_issuer()
        entries = name.get_entries_by_nid_name('O')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationName")
        self.assertEqual(entries[0].get_value(), "Herp Derp plc")

    def test_get_issuer_organizationName(self):
        name = self.cert.get_issuer()
        entries = name.get_entries_by_nid_name('organizationName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationName")
        self.assertEqual(entries[0].get_value(), "Herp Derp plc")

    def test_get_issuer_cn(self):
        name = self.cert.get_issuer()
        entries = name.get_entries_by_nid_name('CN')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "commonName")
        self.assertEqual(entries[0].get_value(), "herp.derp.plc")

    def test_get_issuer_commonName(self):
        name = self.cert.get_issuer()
        entries = name.get_entries_by_nid_name('commonName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "commonName")
        self.assertEqual(entries[0].get_value(), "herp.derp.plc")

    def test_set_subject(self):
        name = x509_name.X509Name()
        name.add_name_entry('C', 'UK')
        self.cert.set_subject(name)

        name = self.cert.get_subject()
        entries = name.get_entries_by_nid_name('C')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "UK")

    def test_set_issuer(self):
        name = x509_name.X509Name()
        name.add_name_entry('C', 'UK')
        self.cert.set_issuer(name)

        name = self.cert.get_issuer()
        entries = name.get_entries_by_nid_name('C')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "UK")
