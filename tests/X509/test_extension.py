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
from pyasn1.codec.der import encoder
from pyasn1.type import univ

from anchor.asn1 import rfc5280
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
        asn1 = rfc5280.Extension()
        asn1['extnID'] = univ.ObjectIdentifier('1.2.3.4')
        asn1['critical'] = False
        asn1['extnValue'] = "foobar"
        ext = extension.X509Extension(asn1)
        self.assertEqual("1.2.3.4: <unknown>", str(ext))

    def test_construct(self):
        asn1 = rfc5280.Extension()
        asn1['extnID'] = univ.ObjectIdentifier('1.2.3.4')
        asn1['critical'] = False
        asn1['extnValue'] = "foobar"
        ext = extension.construct_extension(asn1)
        self.assertIsInstance(ext, extension.X509Extension)

    def test_construct_invalid_type(self):
        with self.assertRaises(errors.X509Error):
            extension.construct_extension("foobar")

    def test_critical(self):
        asn1 = rfc5280.Extension()
        asn1['extnID'] = univ.ObjectIdentifier('1.2.3.4')
        asn1['critical'] = False
        asn1['extnValue'] = "foobar"
        ext = extension.construct_extension(asn1)
        self.assertFalse(ext.get_critical())
        ext.set_critical(True)
        self.assertTrue(ext.get_critical())

    def test_serialise(self):
        asn1 = rfc5280.Extension()
        asn1['extnID'] = univ.ObjectIdentifier('1.2.3.4')
        asn1['critical'] = False
        asn1['extnValue'] = "foobar"
        ext = extension.construct_extension(asn1)
        self.assertEqual(ext.as_der(), encoder.encode(asn1))

    def test_broken_set_value(self):
        class SomeExt(extension.X509Extension):
            spec = rfc5280.Extension
            _oid = univ.ObjectIdentifier('1.2.3.4')

            @classmethod
            def _get_default_value(cls):
                return 1234

        with self.assertRaisesRegexp(errors.X509Error, 'incorrect type'):
            SomeExt()


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
        self.domain = 'example.com'
        self.ip = netaddr.IPAddress('1.2.3.4')
        self.ip6 = netaddr.IPAddress('::1')

    def test_dns_ids(self):
        self.ext.add_dns_id(self.domain)
        self.ext.add_ip(self.ip)
        self.assertEqual([self.domain], self.ext.get_dns_ids())

    def test_add_dns_id_validation(self):
        self.ext.add_dns_id("good.exapmle.com")
        with self.assertRaises(errors.X509Error):
            self.ext.add_dns_id("-blah")

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
        self.assertEqual("subjectAltName: DNS:example.com, IP:1.2.3.4",
                         str(self.ext))


class TestNameConstraints(unittest.TestCase):
    def setUp(self):
        self.ext = extension.X509ExtensionNameConstraints()

    def test_length(self):
        self.assertEqual(0, self.ext.get_permitted_length())
        self.assertEqual(0, self.ext.get_excluded_length())

    def test_add(self):
        test_name = 'example.com'
        test_type = 'dNSName'
        self.assertEqual(0, self.ext.get_permitted_length())
        self.assertEqual(0, self.ext.get_excluded_length())
        self.ext.add_permitted(test_type, test_name)
        self.assertEqual(1, self.ext.get_permitted_length())
        self.assertEqual(0, self.ext.get_excluded_length())
        self.ext.add_excluded(test_type, test_name)
        self.assertEqual(1, self.ext.get_permitted_length())
        self.assertEqual(1, self.ext.get_excluded_length())

    def test_excluded(self):
        self.ext.add_excluded('dNSName', 'example.com')
        self.assertEqual(self.ext.get_excluded_range(0), (0, None))
        self.assertEqual(self.ext.get_excluded_name(0),
                         ('dNSName', b'example.com'))

    def test_permitted(self):
        self.ext.add_permitted('dNSName', 'example.com')
        self.assertEqual(self.ext.get_permitted_range(0), (0, None))
        self.assertEqual(self.ext.get_permitted_name(0),
                         ('dNSName', b'example.com'))


class TestExtendedKeyUsage(unittest.TestCase):
    def setUp(self):
        self.ext = extension.X509ExtensionExtendedKeyUsage()

    def test_get_all(self):
        self.ext.set_usage(rfc5280.id_kp_clientAuth, True)
        self.ext.set_usage(rfc5280.id_kp_codeSigning, True)
        usages = self.ext.get_all_usages()
        self.assertEqual(2, len(usages))
        self.assertIn(rfc5280.id_kp_clientAuth, usages)

    def test_get_one(self):
        self.assertFalse(self.ext.get_usage(rfc5280.id_kp_clientAuth))
        self.ext.set_usage(rfc5280.id_kp_clientAuth, True)
        self.assertTrue(self.ext.get_usage(rfc5280.id_kp_clientAuth))

    def test_set(self):
        self.assertEqual(0, len(self.ext.get_all_usages()))
        self.ext.set_usage(rfc5280.id_kp_clientAuth, True)
        self.assertEqual(1, len(self.ext.get_all_usages()))
        self.ext.set_usage(rfc5280.id_kp_clientAuth, True)
        self.assertEqual(1, len(self.ext.get_all_usages()))
        self.ext.set_usage(rfc5280.id_kp_codeSigning, True)
        self.assertEqual(2, len(self.ext.get_all_usages()))

    def test_unset(self):
        self.ext.set_usage(rfc5280.id_kp_clientAuth, True)
        self.ext.set_usage(rfc5280.id_kp_clientAuth, False)
        self.assertEqual(0, len(self.ext.get_all_usages()))
        self.ext.set_usage(rfc5280.id_kp_clientAuth, False)
        self.assertEqual(0, len(self.ext.get_all_usages()))

    def test_str(self):
        self.ext.set_usage(rfc5280.id_kp_clientAuth, True)
        self.ext.set_usage(rfc5280.id_kp_codeSigning, True)
        self.assertEqual(
            "extKeyUsage: TLS Web Client Authentication, Code Signing",
            str(self.ext))

    def test_invalid_usage(self):
        self.assertRaises(ValueError, self.ext.get_usage,
                          univ.ObjectIdentifier('1.2.3.4'))
        self.assertRaises(ValueError, self.ext.set_usage, True,
                          univ.ObjectIdentifier('1.2.3.4'))


class TestAuthorityKeyId(unittest.TestCase):
    def setUp(self):
        self.ext = extension.X509ExtensionAuthorityKeyId()

    def test_key_id(self):
        key_id = b"12345678"
        self.ext.set_key_id(key_id)
        self.assertEqual(key_id, self.ext.get_key_id())

    def test_name_serial(self):
        s = 12345678
        self.ext.set_serial(s)
        self.assertEqual(s, self.ext.get_serial())


class TestSubjectKeyId(unittest.TestCase):
    def setUp(self):
        self.ext = extension.X509ExtensionSubjectKeyId()

    def test_key_id(self):
        key_id = b"12345678"
        self.ext.set_key_id(key_id)
        self.assertEqual(key_id, self.ext.get_key_id())
