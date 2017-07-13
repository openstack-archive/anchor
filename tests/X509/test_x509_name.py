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

from anchor.X509 import errors as x509_errors
from anchor.X509 import name as x509_name


class TestX509Name(unittest.TestCase):
    def setUp(self):
        super(TestX509Name, self).setUp()
        self.name = x509_name.X509Name()
        self.name.add_name_entry(x509_name.OID_countryName,
                                 "UK")  # must be 2 chars
        self.name.add_name_entry(x509_name.OID_stateOrProvinceName, "test_ST")
        self.name.add_name_entry(x509_name.OID_localityName, "test_L")
        self.name.add_name_entry(x509_name.OID_organizationName, "test_O")
        self.name.add_name_entry(x509_name.OID_organizationalUnitName,
                                 "test_OU")
        self.name.add_name_entry(x509_name.OID_commonName, "test_CN")
        self.name.add_name_entry(x509_name.OID_pkcs9_emailAddress,
                                 "test_Email")
        self.name.add_name_entry(x509_name.OID_surname, "test_SN")
        self.name.add_name_entry(x509_name.OID_givenName, "test_GN")

    def tearDown(self):
        pass

    def test_add_bad_entry_throws(self):
        self.assertRaises(x509_errors.X509Error,
                          self.name.add_name_entry,
                          -1, "BAD_WRONG")

    def test_set_bad_c_throws(self):
        self.assertRaises(x509_errors.X509Error,
                          self.name.add_name_entry,
                          x509_name.OID_countryName, "BAD_WRONG")

    def test_name_to_string(self):
        val = str(self.name)
        self.assertEqual(("/C=UK/ST=test_ST/L=test_L/O=test_O/OU=test_OU"
                          "/CN=test_CN/emailAddress=test_Email/"
                          "SN=test_SN/GN=test_GN"), val)

    def test_get_countryName(self):
        entries = self.name.get_entries_by_oid(x509_name.OID_countryName)
        self.assertEqual(1, len(entries))
        self.assertEqual("countryName", entries[0].get_name())
        self.assertEqual("UK", entries[0].get_value())

    def test_get_stateOrProvinceName(self):
        entries = self.name.get_entries_by_oid(
            x509_name.OID_stateOrProvinceName)
        self.assertEqual(1, len(entries))
        self.assertEqual("stateOrProvinceName", entries[0].get_name())
        self.assertEqual("test_ST", entries[0].get_value())

    def test_get_subject_localityName(self):
        entries = self.name.get_entries_by_oid(x509_name.OID_localityName)
        self.assertEqual(1, len(entries))
        self.assertEqual("localityName", entries[0].get_name())
        self.assertEqual("test_L", entries[0].get_value())

    def test_get_organizationName(self):
        entries = self.name.get_entries_by_oid(x509_name.OID_organizationName)
        self.assertEqual(1, len(entries))
        self.assertEqual("organizationName", entries[0].get_name())
        self.assertEqual("test_O", entries[0].get_value())

    def test_get_organizationUnitName(self):
        entries = self.name.get_entries_by_oid(
            x509_name.OID_organizationalUnitName)
        self.assertEqual(1, len(entries))
        self.assertEqual("organizationalUnitName", entries[0].get_name())
        self.assertEqual("test_OU", entries[0].get_value())

    def test_get_commonName(self):
        entries = self.name.get_entries_by_oid(x509_name.OID_commonName)
        self.assertEqual(1, len(entries))
        self.assertEqual("commonName", entries[0].get_name())
        self.assertEqual("test_CN", entries[0].get_value())

    def test_get_emailAddress(self):
        entries = self.name.get_entries_by_oid(
            x509_name.OID_pkcs9_emailAddress)
        self.assertEqual(1, len(entries))
        self.assertEqual("emailAddress", entries[0].get_name())
        self.assertEqual("test_Email", entries[0].get_value())

    def test_entry_to_string(self):
        entries = self.name.get_entries_by_oid(
            x509_name.OID_pkcs9_emailAddress)
        self.assertEqual(1, len(entries))
        self.assertEqual("emailAddress: test_Email", str(entries[0]))

    def test_entry_length(self):
        num = len(self.name)
        self.assertEqual(9, num)

    def test_entry_index_good(self):
        self.assertEqual("givenName: test_GN", str(self.name[8]))

    def test_entry_index_bad(self):
        with self.assertRaises(IndexError):
            self.name[9]

    def test_entry_itter(self):
        val = [str(e) for e in self.name]
        self.assertEqual("countryName: UK", val[0])
        self.assertEqual("givenName: test_GN", val[8])

    def test_deep_clone(self):
        orig = x509_name.X509Name()
        orig.add_name_entry(x509_name.OID_countryName, "UK")
        clone = x509_name.X509Name(orig._name_obj)
        self.assertEqual(str(orig), str(clone))
        clone.add_name_entry(x509_name.OID_stateOrProvinceName, "test_ST")
        self.assertNotEqual(str(orig), str(clone))
