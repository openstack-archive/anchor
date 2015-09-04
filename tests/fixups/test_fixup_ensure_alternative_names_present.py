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

import netaddr

from anchor import fixups
from anchor.X509 import extension
from anchor.X509 import name
from anchor.X509 import signing_request


class TestEnsureAlternativeNamesPresent(unittest.TestCase):
    def setUp(self):
        super(TestEnsureAlternativeNamesPresent, self).setUp()

    def _csr_with_cn(self, cn):
        csr = signing_request.X509Csr()
        subject = name.X509Name()
        subject.add_name_entry(name.OID_commonName, cn)
        csr.set_subject(subject)
        return csr

    def test_no_cn(self):
        csr = signing_request.X509Csr()
        subject = name.X509Name()
        subject.add_name_entry(name.OID_localityName, "somewhere")
        csr.set_subject(subject)

        new_csr = fixups.enforce_alternative_names_present(csr=csr)
        self.assertEqual(0, len(new_csr.get_extensions()))

    def test_cn_only_ip(self):
        csr = self._csr_with_cn("1.2.3.4")

        new_csr = fixups.enforce_alternative_names_present(csr=csr)
        self.assertEqual(1, len(new_csr.get_extensions()))
        ext = new_csr.get_extensions(extension.X509ExtensionSubjectAltName)[0]
        self.assertEqual([netaddr.IPAddress("1.2.3.4")], ext.get_ips())

    def test_cn_only_dns(self):
        csr = self._csr_with_cn("example.com")

        new_csr = fixups.enforce_alternative_names_present(csr=csr)
        self.assertEqual(1, len(new_csr.get_extensions()))
        ext = new_csr.get_extensions(extension.X509ExtensionSubjectAltName)[0]
        self.assertEqual(["example.com"], ext.get_dns_ids())

    def test_cn_existing_ip(self):
        csr = self._csr_with_cn("1.2.3.4")
        san = extension.X509ExtensionSubjectAltName()
        san.add_ip(netaddr.IPAddress("1.2.3.4"))
        csr.add_extension(san)

        new_csr = fixups.enforce_alternative_names_present(csr=csr)
        self.assertEqual(1, len(new_csr.get_extensions()))
        ext = new_csr.get_extensions(extension.X509ExtensionSubjectAltName)[0]
        self.assertEqual([netaddr.IPAddress("1.2.3.4")], ext.get_ips())

    def test_cn_existing_dns(self):
        csr = self._csr_with_cn("example.com")
        san = extension.X509ExtensionSubjectAltName()
        san.add_dns_id("example.com")
        csr.add_extension(san)

        new_csr = fixups.enforce_alternative_names_present(csr=csr)
        self.assertEqual(1, len(new_csr.get_extensions()))
        ext = new_csr.get_extensions(extension.X509ExtensionSubjectAltName)[0]
        self.assertEqual(["example.com"], ext.get_dns_ids())

    def test_cn_extra_ip(self):
        csr = self._csr_with_cn("1.2.3.4")
        san = extension.X509ExtensionSubjectAltName()
        san.add_ip(netaddr.IPAddress("2.3.4.5"))
        csr.add_extension(san)

        new_csr = fixups.enforce_alternative_names_present(csr=csr)
        self.assertEqual(1, len(new_csr.get_extensions()))
        ext = new_csr.get_extensions(extension.X509ExtensionSubjectAltName)[0]
        ips = ext.get_ips()
        self.assertIn(netaddr.IPAddress("1.2.3.4"), ips)
        self.assertIn(netaddr.IPAddress("2.3.4.5"), ips)

    def test_cn_extra_dns(self):
        csr = self._csr_with_cn("example.com")
        san = extension.X509ExtensionSubjectAltName()
        san.add_dns_id("other.example.com")
        csr.add_extension(san)

        new_csr = fixups.enforce_alternative_names_present(csr=csr)
        self.assertEqual(1, len(new_csr.get_extensions()))
        ext = new_csr.get_extensions(extension.X509ExtensionSubjectAltName)[0]
        ids = ext.get_dns_ids()
        self.assertIn("example.com", ids)
        self.assertIn("other.example.com", ids)
