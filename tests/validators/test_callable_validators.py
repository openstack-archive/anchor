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

import base64
import unittest

import mock
import netaddr
from pyasn1.codec.der import decoder

from anchor.asn1 import rfc5280
from anchor.validators import custom
from anchor.validators import errors
from anchor.validators import internal
from anchor.validators import utils
from anchor.X509 import extension as x509_ext
from anchor.X509 import name as x509_name
from anchor.X509 import signing_request as x509_csr
import tests


class TestValidators(tests.DefaultRequestMixin, unittest.TestCase):
    def setUp(self):
        super(TestValidators, self).setUp()

    def tearDown(self):
        super(TestValidators, self).tearDown()

    def _csr_with_cn(self, cn):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, cn)
        csr.set_subject(name)
        return csr

    def _csr_with_san_dns(self, dns):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id(dns)
        csr.add_extension(ext)
        return csr

    def test_check_networks_good(self):
        allowed_networks = ['15/8', '74.125/16']
        self.assertTrue(utils.check_networks(
            netaddr.IPAddress('74.125.224.64'), allowed_networks))

    def test_check_networks_bad(self):
        allowed_networks = ['15/8', '74.125/16']
        self.assertFalse(utils.check_networks(
            netaddr.IPAddress('12.2.2.2'), allowed_networks))

    def test_check_domains_empty(self):
        self.assertTrue(utils.check_domains(
            'example.com', []))

    def test_common_name_with_two_CN(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, "dummy_value")
        name.add_name_entry(x509_name.OID_commonName, "dummy_value")
        csr.set_subject(name)

        with self.assertRaises(errors.ValidationError) as e:
            custom.common_name(
                csr=csr,
                allowed_domains=[],
                allowed_networks=[])
        self.assertEqual("Too many CNs in the request", str(e.exception))

    def test_common_name_no_CN(self):
        csr = x509_csr.X509Csr()

        with self.assertRaises(errors.ValidationError) as e:
            custom.common_name(
                csr=csr,
                allowed_domains=[],
                allowed_networks=[])
        self.assertEqual("Alt subjects have to exist if the main subject"
                         " doesn't", str(e.exception))

    def test_common_name_good_CN(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, "good.example.com")
        csr.set_subject(name)

        self.assertEqual(
            None,
            custom.common_name(
                csr=csr,
                allowed_domains=['.example.com'],
            )
        )

    def test_common_name_bad_CN(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, 'bad.example.org')
        csr.set_subject(name)

        with self.assertRaises(errors.ValidationError) as e:
            custom.common_name(
                csr=csr,
                allowed_domains=['.example.com'])
        self.assertEqual("Domain 'bad.example.org' not allowed (does not "
                         "match known domains)", str(e.exception))

    def test_common_name_ip_good(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, '10.1.1.1')
        csr.set_subject(name)

        self.assertEqual(
            None,
            custom.common_name(
                csr=csr,
                allowed_domains=['.example.com'],
                allowed_networks=['10/8']
            )
        )

    def test_common_name_ip_bad(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, '15.1.1.1')
        csr.set_subject(name)

        with self.assertRaises(errors.ValidationError) as e:
            custom.common_name(
                csr=csr,
                allowed_domains=['.example.com'],
                allowed_networks=['10/8'])
        self.assertEqual("Address '15.1.1.1' not allowed (does not "
                         "match known networks)", str(e.exception))

    def test_alternative_names_good_domain(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('good.example.com')
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.alternative_names(
                csr=csr,
                allowed_domains=['.example.com'],
            )
        )

    def test_alternative_names_bad_domain(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('bad.example.org')
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            custom.alternative_names(
                csr=csr,
                allowed_domains=['.example.com'])
        self.assertEqual("Domain 'bad.example.org' not allowed (doesn't "
                         "match known domains)", str(e.exception))

    def test_alternative_names_ip_good(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_ip(netaddr.IPAddress('10.1.1.1'))
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.alternative_names_ip(
                csr=csr,
                allowed_domains=['.example.com'],
                allowed_networks=['10/8']
            )
        )

    def test_alternative_names_ip_bad(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_ip(netaddr.IPAddress('10.1.1.1'))
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            custom.alternative_names_ip(
                csr=csr,
                allowed_domains=['.example.com'],
                allowed_networks=['99/8'])
        self.assertEqual("IP '10.1.1.1' not allowed (doesn't match known "
                         "networks)", str(e.exception))

    def test_alternative_names_ip_bad_domain(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('bad.example.org')
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            custom.alternative_names_ip(
                csr=csr,
                allowed_domains=['.example.com'])
        self.assertEqual("Domain 'bad.example.org' not allowed (doesn't "
                         "match known domains)", str(e.exception))

    def test_server_group_no_prefix1(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, "master.example.com")
        csr.set_subject(name)

        self.assertEqual(
            None,
            custom.server_group(
                auth_result=None,
                csr=csr,
                group_prefixes={}
            )
        )

    def test_server_group_no_prefix2(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, "nv_master.example.com")
        csr.set_subject(name)

        self.assertEqual(
            None,
            custom.server_group(
                auth_result=None,
                csr=csr,
                group_prefixes={}
            )
        )

    def test_server_group_good_prefix(self):
        # 'nv' in prefix means only Nova members should be able to issue
        auth_result = mock.Mock()
        auth_result.groups = ['nova']

        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, "nv_master.example.com")
        csr.set_subject(name)

        self.assertEqual(
            None,
            custom.server_group(
                auth_result=auth_result,
                csr=csr,
                group_prefixes={'nv': 'nova', 'sw': 'swift'}
            )
        )

    def test_server_group_bad(self):
        auth_result = mock.Mock()
        auth_result.groups = ['glance']

        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, "nv-master.example.com")
        csr.set_subject(name)

        with self.assertRaises(errors.ValidationError) as e:
            custom.server_group(
                auth_result=auth_result,
                csr=csr,
                group_prefixes={'nv': 'nova', 'sw': 'swift'})
        self.assertEqual("Server prefix doesn't match user groups",
                         str(e.exception))

    def test_extensions_bad(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('keyCertSign', True)
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            custom.extensions(
                csr=csr,
                allowed_extensions=['basicConstraints', 'nameConstraints'])
        self.assertEqual("Extension 'keyUsage' not allowed", str(e.exception))

    def test_extensions_good_name(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('keyCertSign', True)
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.extensions(
                csr=csr,
                allowed_extensions=['basicConstraints', 'keyUsage']
            )
        )

    def test_extensions_good_oid(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('keyCertSign', True)
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.extensions(
                csr=csr,
                allowed_extensions=['basicConstraints', '2.5.29.15']
            )
        )

    def test_key_usage_bad(self):
        allowed_usage = ['Digital Signature',
                         'Non Repudiation',
                         'Key Encipherment']

        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('keyCertSign', True)
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            custom.key_usage(
                csr=csr,
                allowed_usage=allowed_usage)
        self.assertEqual("Found some prohibited key usages: "
                         "keyCertSign", str(e.exception))

    def test_key_usage_good(self):
        allowed_usage = ['Digital Signature',
                         'Non Repudiation',
                         'Key Encipherment']

        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('keyEncipherment', True)
        ext.set_usage('digitalSignature', True)
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.key_usage(
                csr=csr,
                allowed_usage=allowed_usage
            )
        )

    def test_ext_key_usage_good_short(self):
        allowed_usage = ['serverAuth']

        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionExtendedKeyUsage()
        ext.set_usage(rfc5280.id_kp_serverAuth, True)
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.ext_key_usage(
                csr=csr,
                allowed_usage=allowed_usage
            )
        )

    def test_ext_key_usage_good_long(self):
        allowed_usage = ['TLS Web Server Authentication']

        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionExtendedKeyUsage()
        ext.set_usage(rfc5280.id_kp_serverAuth, True)
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.ext_key_usage(
                csr=csr,
                allowed_usage=allowed_usage
            )
        )

    def test_ext_key_usage_good_oid(self):
        allowed_usage = ["1.3.6.1.5.5.7.3.1"]

        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionExtendedKeyUsage()
        ext.set_usage(rfc5280.id_kp_serverAuth, True)
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.ext_key_usage(
                csr=csr,
                allowed_usage=allowed_usage
            )
        )

    def test_ext_key_usage_bad(self):
        allowed_usage = ['serverAuth']

        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionExtendedKeyUsage()
        ext.set_usage(rfc5280.id_kp_clientAuth, True)
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            custom.ext_key_usage(
                csr=csr,
                allowed_usage=allowed_usage)
        self.assertEqual("Found some prohibited key usages: "
                         "clientAuth", str(e.exception))

    def test_ca_status_good(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionBasicConstraints()
        ext.set_ca(False)
        csr.add_extension(ext)

        self.assertIsNone(internal.ca_status(csr=csr))

    def test_ca_status_forbidden(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionBasicConstraints()
        ext.set_ca(True)
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            internal.ca_status(csr=csr)
        self.assertEqual("Request is for a CA certificate",
                         str(e.exception))

    def test_ca_status_pathlen(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionBasicConstraints()
        ext.set_path_len_constraint(1)
        csr.add_extension(ext)

        self.assertIsNone(internal.ca_status(csr=csr))

    def test_ca_status_key_usage_bad1(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('keyCertSign', True)
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            internal.ca_status(csr=csr)
        self.assertEqual("Request contains certificates signing usage flag",
                         str(e.exception))

    def test_ca_status_key_usage_bad2(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('cRLSign', True)
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            internal.ca_status(csr=csr)
        self.assertEqual("Request contains CRL signing usage flag",
                         str(e.exception))

    def test_source_cidrs_good(self):
        request = mock.Mock(client_addr='127.0.0.1')
        self.assertEqual(
            None,
            custom.source_cidrs(
                request=request,
                cidrs=['127/8', '10/8']
            )
        )

    def test_source_cidrs_out_of_range(self):
        request = mock.Mock(client_addr='99.0.0.1')
        with self.assertRaises(errors.ValidationError) as e:
            custom.source_cidrs(
                request=request,
                cidrs=['127/8', '10/8'])
        self.assertEqual("No network matched the request source '99.0.0.1'",
                         str(e.exception))

    def test_source_cidrs_bad_cidr(self):
        request = mock.Mock(client_addr='127.0.0.1')
        with self.assertRaises(errors.ValidationError) as e:
            custom.source_cidrs(
                request=request,
                cidrs=['bad'])
        self.assertEqual("Cidr 'bad' does not describe a valid network",
                         str(e.exception))

    def test_blacklist_names_good(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('good.example.com')
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.blacklist_names(
                csr=csr,
                domains=['.example.org'],
            )
        )

    def test_blacklist_names_bad(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('bad.example.com')
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError):
            custom.blacklist_names(
                csr=csr,
                domains=['.example.com'],
            )

    def test_blacklist_names_bad_cn(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, "bad.example.com")
        csr.set_subject(name)

        with self.assertRaises(errors.ValidationError):
            custom.blacklist_names(
                csr=csr,
                domains=['.example.com'],
            )

    def test_blacklist_names_mix(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('bad.example.org')
        ext.add_dns_id('good.example.com')
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError):
            custom.blacklist_names(
                csr=csr,
                domains=['.example.org'],
            )

    def test_blacklist_names_empty_list(self):
        # empty blacklist should pass everything through
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('good.example.com')
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.blacklist_names(
                csr=csr,
            )
        )

    def test_public_key_good_rsa(self):
        csr = x509_csr.X509Csr.from_buffer(self.csr_sample_bytes)
        self.assertIsNone(custom.public_key(csr=csr,
                                            allowed_keys={'RSA': 1024}))

    def test_public_key_good_dsa(self):
        dsa_key_pem = """
        MIIBtjCCASsGByqGSM44BAEwggEeAoGBAJv/ZwltxEMrACE71R+AvxOuvWgTIKAd
        iVq9ATbcuiaMq5P+iyhsI0k5A29bLNxkU/kkUCBYEEOoM2R1+8eO6UVr40+dtVw8
        OzqHI6nFVmWMNUDGdPFoIIWsh5KRavhgy3Z8CKDqvGf4hxR1QWEN4Jz51xtHS3fI
        1SKJybWdu2ifAhUAgoQ1AiWH9zLU6AOafUdv6iNdxKsCgYA66IS+XsIZwQvkHJkA
        rf9hbOGC8aZeuafm7PlU6C+7TRB+7hoPzrwkn0ROYhv3yGsFYKWBEjAorW/skNJQ
        cmdPsZV9tGdkfyvj5lxmAAbu+4ofozUvwKlSvpa/e/PLY7aZCq8u+fSHsF+xpUNl
        GlCRV1DL13tDWZb+XS8w7RD3EQOBhAACgYBu77erOhm/hF6l6u6wuyaM0GfgdMxg
        eU5WnfcTJOzXXZBcv3cetn/OF0OG3e81R+/78xIjpx+b1q5bjXvqNRfZWr8Vov+Y
        ox6WOB2kdxa+tRgpK1Bs6FqJgI7AWMYVSxgjpx+9Q/j6aZe6+r8m6k9HOU0cw+0L
        7PFU2eVGvF/DYA==
        """
        dsa_key_der = base64.b64decode(dsa_key_pem)
        spki = decoder.decode(dsa_key_der,
                              asn1Spec=rfc5280.SubjectPublicKeyInfo())[0]
        csr = x509_csr.X509Csr.from_buffer(self.csr_sample_bytes)
        csr._csr['certificationRequestInfo']['subjectPublicKeyInfo'] = spki
        self.assertIsNone(custom.public_key(csr=csr,
                                            allowed_keys={'DSA': 1024}))

    def test_public_key_too_short(self):
        csr = x509_csr.X509Csr.from_buffer(self.csr_sample_bytes)
        with self.assertRaises(errors.ValidationError):
            custom.public_key(csr=csr, allowed_keys={'RSA': 99999999})

    def test_public_key_wrong_algo(self):
        csr = x509_csr.X509Csr.from_buffer(self.csr_sample_bytes)
        with self.assertRaises(errors.ValidationError):
            custom.public_key(csr=csr, allowed_keys={'XXX': 0})

    def test_whitelist_names_empty_list(self):
        # empty whitelist should block everything
        csr = self._csr_with_san_dns('example.com')

        with self.assertRaises(errors.ValidationError):
            custom.whitelist_names(csr=csr, domains=[],)

    def test_whitelist_names_full_dnsid_match(self):
        csr = self._csr_with_san_dns('example.com')
        custom.whitelist_names(csr=csr, allow_dns_id=True,
                               names=['example.com'])

    def test_whitelist_names_partial_dnsid_match(self):
        csr = self._csr_with_san_dns('good-123.example.com')
        custom.whitelist_names(csr=csr, allow_dns_id=True,
                               names=['good-%.example.com'])

    def test_whitelist_names_full_dnsid_fail(self):
        csr = self._csr_with_san_dns('bad.example.com')
        with self.assertRaises(errors.ValidationError):
            custom.whitelist_names(csr=csr, allow_dns_id=True,
                                   names=['good.example.com'])

    def test_whitelist_names_full_ipid_match(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_ip(netaddr.IPAddress('1.2.3.4'))
        csr.add_extension(ext)

        custom.whitelist_names(csr=csr, allow_ip_id=True, names=['1.2.3.4'])

    def test_whitelist_names_full_ipid_fail(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_ip(netaddr.IPAddress('4.3.2.1'))
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError):
            custom.whitelist_names(csr=csr, allow_ip_id=True,
                                   names=['1.2.3.4'])

    def test_whitelist_names_cn_not_allowed(self):
        csr = self._csr_with_cn("bad.example.com")
        with self.assertRaises(errors.ValidationError):
            custom.whitelist_names(csr=csr, names=[],)

    def test_whitelist_names_cn_ip_fail(self):
        csr = self._csr_with_cn("4.3.2.1")
        with self.assertRaises(errors.ValidationError):
            custom.whitelist_names(csr=csr, allow_cn_id=True,
                                   names=["1.2.3.4"])

    def test_whitelist_names_cn_ip_match(self):
        csr = self._csr_with_cn("1.2.3.4")
        custom.whitelist_names(csr=csr, allow_cn_id=True, names=["1.2.3.4"])

    def test_whitelist_names_cn_ip_net_fail(self):
        csr = self._csr_with_cn("4.3.2.1")
        with self.assertRaises(errors.ValidationError):
            custom.whitelist_names(csr=csr, allow_cn_id=True, names=["1/8"])

    def test_whitelist_names_cn_ip_net_match(self):
        csr = self._csr_with_cn("1.2.3.4")
        custom.whitelist_names(csr=csr, allow_cn_id=True, names=["1/8"])

    def test_whitelist_names_cn_name_fail(self):
        csr = self._csr_with_cn("bad.example.com")
        with self.assertRaises(errors.ValidationError):
            custom.whitelist_names(csr=csr, allow_cn_id=True,
                                   names=["good.example.com"])

    def test_whitelist_names_cn_name_match(self):
        csr = self._csr_with_cn("good.example.com")
        custom.whitelist_names(csr=csr, allow_cn_id=True,
                               names=["good.example.com"])

    def test_whitelist_names_cn_partial_name_fail(self):
        csr = self._csr_with_cn("bad.example.com")
        with self.assertRaises(errors.ValidationError):
            custom.whitelist_names(csr=csr, allow_cn_id=True,
                                   names=[".good.example.com"])

    def test_whitelist_names_cn_partial_name_match(self):
        csr = self._csr_with_cn("good.example.com")
        custom.whitelist_names(csr=csr, allow_cn_id=True,
                               names=["%.example.com"])
