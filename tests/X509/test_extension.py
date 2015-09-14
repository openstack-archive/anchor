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

import netaddr
from pyasn1_modules import rfc2459  # X509v3

from anchor.X509 import errors
from anchor.X509 import extension


class TestExtensionBase(unittest.TestCase):
    def test_no_spec(self):
        with self.assertRaises(errors.X509Error):
            extension.X509Extension()

    def test_invalid_asn(self):
        with self.assertRaises(errors.X509Error):
            extension.X509Extension("foobar")

    def test_unknown_extension_str(self):
        asn1 = rfc2459.Extension()
        asn1['extnID'] = rfc2459.univ.ObjectIdentifier('1.2.3.4')
        asn1['critical'] = False
        asn1['extnValue'] = "foobar"
        ext = extension.X509Extension(asn1)
        self.assertEqual("1.2.3.4: <unknown>", str(ext))

    def test_construct(self):
        asn1 = rfc2459.Extension()
        asn1['extnID'] = rfc2459.univ.ObjectIdentifier('1.2.3.4')
        asn1['critical'] = False
        asn1['extnValue'] = "foobar"
        ext = extension.construct_extension(asn1)
        self.assertIsInstance(ext, extension.X509Extension)

    def test_construct_invalid_type(self):
        with self.assertRaises(errors.X509Error):
            extension.construct_extension("foobar")

    def test_critical(self):
        asn1 = rfc2459.Extension()
        asn1['extnID'] = rfc2459.univ.ObjectIdentifier('1.2.3.4')
        asn1['critical'] = False
        asn1['extnValue'] = "foobar"
        ext = extension.construct_extension(asn1)
        self.assertFalse(ext.get_critical())
        ext.set_critical(True)
        self.assertTrue(ext.get_critical())


class TestBasicConstraints(unittest.TestCase):
    def setUp(self):
        self.ext = extension.X509ExtensionBasicConstraints()

    def test_str(self):
        self.assertEqual(str(self.ext),
                         "basicConstraints: CA: FALSE, pathLen: None")

    def test_ca(self):
        self.ext.set_ca(True)
        self.assertTrue(self.ext.get_ca())
        self.ext.set_ca(False)
        self.assertFalse(self.ext.get_ca())

    def test_pathlen(self):
        self.ext.set_path_len_constraint(1)
        self.assertEqual(1, self.ext.get_path_len_constraint())


class TestKeyUsage(unittest.TestCase):
    def setUp(self):
        self.ext = extension.X509ExtensionKeyUsage()

    def test_usage_set(self):
        self.ext.set_usage('digitalSignature', True)
        self.ext.set_usage('keyAgreement', False)
        self.assertTrue(self.ext.get_usage('digitalSignature'))
        self.assertFalse(self.ext.get_usage('keyAgreement'))

    def test_usage_reset(self):
        self.ext.set_usage('digitalSignature', True)
        self.ext.set_usage('digitalSignature', False)
        self.assertFalse(self.ext.get_usage('digitalSignature'))

    def test_usage_unset(self):
        self.assertFalse(self.ext.get_usage('keyAgreement'))

    def test_get_all_usage(self):
        self.ext.set_usage('digitalSignature', True)
        self.ext.set_usage('keyAgreement', False)
        self.ext.set_usage('keyEncipherment', True)
        self.assertEqual(set(['digitalSignature', 'keyEncipherment']),
                         set(self.ext.get_all_usages()))

    def test_str(self):
        self.ext.set_usage('digitalSignature', True)
        self.assertEqual("keyUsage: digitalSignature", str(self.ext))


class TestSubjectAltName(unittest.TestCase):
    def setUp(self):
        self.ext = extension.X509ExtensionSubjectAltName()
        self.domain = 'some.domain'
        self.ip = netaddr.IPAddress('1.2.3.4')
        self.ip6 = netaddr.IPAddress('::1')

    def test_dns_ids(self):
        self.ext.add_dns_id(self.domain)
        self.ext.add_ip(self.ip)
        self.assertEqual([self.domain], self.ext.get_dns_ids())

    def test_ips(self):
        self.ext.add_dns_id(self.domain)
        self.ext.add_ip(self.ip)
        self.assertEqual([self.ip], self.ext.get_ips())

    def test_ipv6(self):
        self.ext.add_ip(self.ip6)
        self.assertEqual([self.ip6], self.ext.get_ips())

    def test_add_ip_invalid(self):
        with self.assertRaises(errors.X509Error):
            self.ext.add_ip("abcdef")

    def test_str(self):
        self.ext.add_dns_id(self.domain)
        self.ext.add_ip(self.ip)
        self.assertEqual("subjectAltName: DNS:some.domain, IP:1.2.3.4",
                         str(self.ext))


class TestExtendedKeyUsage(unittest.TestCase):
    def setUp(self):
        self.ext = extension.X509ExtensionExtendedKeyUsage()

    def test_get_all(self):
        self.ext.set_usage(rfc2459.id_kp_clientAuth, True)
        self.ext.set_usage(rfc2459.id_kp_codeSigning, True)
        usages = self.ext.get_all_usages()
        self.assertEqual(2, len(usages))
        self.assertIn(rfc2459.id_kp_clientAuth, usages)

    def test_get_one(self):
        self.assertFalse(self.ext.get_usage(rfc2459.id_kp_clientAuth))
        self.ext.set_usage(rfc2459.id_kp_clientAuth, True)
        self.assertTrue(self.ext.get_usage(rfc2459.id_kp_clientAuth))

    def test_set(self):
        self.assertEqual(0, len(self.ext.get_all_usages()))
        self.ext.set_usage(rfc2459.id_kp_clientAuth, True)
        self.assertEqual(1, len(self.ext.get_all_usages()))
        self.ext.set_usage(rfc2459.id_kp_clientAuth, True)
        self.assertEqual(1, len(self.ext.get_all_usages()))

    def test_unset(self):
        self.ext.set_usage(rfc2459.id_kp_clientAuth, True)
        self.ext.set_usage(rfc2459.id_kp_clientAuth, False)
        self.assertEqual(0, len(self.ext.get_all_usages()))
        self.ext.set_usage(rfc2459.id_kp_clientAuth, False)
        self.assertEqual(0, len(self.ext.get_all_usages()))

    def test_str(self):
        self.ext.set_usage(rfc2459.id_kp_clientAuth, True)
        self.ext.set_usage(rfc2459.id_kp_codeSigning, True)
        self.assertEqual(
            "extKeyUsage: TLS Web Client Authentication, Code Signing",
            str(self.ext))
