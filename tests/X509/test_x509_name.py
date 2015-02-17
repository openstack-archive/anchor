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
        self.name.add_name_entry('C', "UK")  # must be 2 chars
        self.name.add_name_entry('ST', "test_ST")
        self.name.add_name_entry('L', "test_L")
        self.name.add_name_entry('O', "test_O")
        self.name.add_name_entry('OU', "test_OU")
        self.name.add_name_entry('CN', "test_CN")
        self.name.add_name_entry('Email', "test_Email")
        self.name.add_name_entry('SN', "test_SN")
        self.name.add_name_entry('GN', "test_GN")

    def tearDown(self):
        pass

    def test_add_bad_entry_throws(self):
        self.assertRaises(x509_errors.X509Error,
                          self.name.add_name_entry,
                          'BAD', "BAD_WRONG")

    def test_set_bad_c_throws(self):
        self.assertRaises(x509_errors.X509Error,
                          self.name.add_name_entry,
                          'C', "BAD_WRONG")

    def test_name_to_string(self):
        val = str(self.name)
        self.assertEqual(val, ("/C=UK/ST=test_ST/L=test_L/O=test_O/OU=test_OU"
                               "/CN=test_CN/emailAddress=test_Email/"
                               "SN=test_SN/GN=test_GN"))

    def test_get_c(self):
        entries = self.name.get_entries_by_nid_name('C')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "UK")

    def test_get_countryName(self):
        entries = self.name.get_entries_by_nid_name('countryName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "UK")

    def test_get_st(self):
        entries = self.name.get_entries_by_nid_name('ST')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "stateOrProvinceName")
        self.assertEqual(entries[0].get_value(), "test_ST")

    def test_get_sp(self):
        entries = self.name.get_entries_by_nid_name('SP')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "stateOrProvinceName")
        self.assertEqual(entries[0].get_value(), "test_ST")

    def test_get_stateOrProvinceName(self):
        entries = self.name.get_entries_by_nid_name('stateOrProvinceName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "stateOrProvinceName")
        self.assertEqual(entries[0].get_value(), "test_ST")

    def test_get_l(self):
        entries = self.name.get_entries_by_nid_name('L')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "localityName")
        self.assertEqual(entries[0].get_value(), "test_L")

    def test_get_subject_localityName(self):
        entries = self.name.get_entries_by_nid_name('localityName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "localityName")
        self.assertEqual(entries[0].get_value(), "test_L")

    def test_get_o(self):
        entries = self.name.get_entries_by_nid_name('O')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationName")
        self.assertEqual(entries[0].get_value(), "test_O")

    def test_get_organizationName(self):
        entries = self.name.get_entries_by_nid_name('organizationName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationName")
        self.assertEqual(entries[0].get_value(), "test_O")

    def test_get_ou(self):
        entries = self.name.get_entries_by_nid_name('OU')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationalUnitName")
        self.assertEqual(entries[0].get_value(), "test_OU")

    def test_get_organizationUnitName(self):
        entries = self.name.get_entries_by_nid_name('organizationalUnitName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationalUnitName")
        self.assertEqual(entries[0].get_value(), "test_OU")

    def test_get_cn(self):
        entries = self.name.get_entries_by_nid_name('CN')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "commonName")
        self.assertEqual(entries[0].get_value(), "test_CN")

    def test_get_commonName(self):
        entries = self.name.get_entries_by_nid_name('commonName')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "commonName")
        self.assertEqual(entries[0].get_value(), "test_CN")

    def test_get_email(self):
        entries = self.name.get_entries_by_nid_name('Email')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "emailAddress")
        self.assertEqual(entries[0].get_value(), "test_Email")

    def test_get_emailAddress(self):
        entries = self.name.get_entries_by_nid_name('Email')
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "emailAddress")
        self.assertEqual(entries[0].get_value(), "test_Email")
