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

import mock
import netaddr
from pyasn1_modules import rfc2459

from anchor.validators import custom
from anchor.validators import errors
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
        ext.set_usage(rfc2459.id_kp_serverAuth, True)
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
        ext.set_usage(rfc2459.id_kp_serverAuth, True)
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
        ext.set_usage(rfc2459.id_kp_serverAuth, True)
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
        ext.set_usage(rfc2459.id_kp_clientAuth, True)
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            custom.ext_key_usage(
                csr=csr,
                allowed_usage=allowed_usage)
        self.assertEqual("Found some prohibited key usages: "
                         "clientAuth", str(e.exception))

    def test_ca_status_good1(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionBasicConstraints()
        ext.set_ca(True)
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.ca_status(
                csr=csr,
                ca_requested=True
            )
        )

    def test_ca_status_good2(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionBasicConstraints()
        ext.set_ca(False)
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.ca_status(
                csr=csr,
                ca_requested=False
            )
        )

    def test_ca_status_forbidden(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionBasicConstraints()
        ext.set_ca(True)
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            custom.ca_status(
                csr=csr,
                ca_requested=False)
        self.assertEqual("CA status requested, but not allowed",
                         str(e.exception))

    def test_ca_status_bad(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionBasicConstraints()
        ext.set_ca(False)
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            custom.ca_status(
                csr=csr,
                ca_requested=True)
        self.assertEqual("CA flags required",
                         str(e.exception))

    def test_ca_status_pathlen(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionBasicConstraints()
        ext.set_path_len_constraint(1)
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.ca_status(
                csr=csr,
                ca_requested=False
            )
        )

    def test_ca_status_key_usage_bad1(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('keyCertSign', True)
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            custom.ca_status(
                csr=csr,
                ca_requested=False)
        self.assertEqual("Key usage doesn't match requested CA status "
                         "(keyCertSign/cRLSign: True/False)", str(e.exception))

    def test_ca_status_key_usage_good1(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('keyCertSign', True)
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.ca_status(
                csr=csr,
                ca_requested=True
            )
        )

    def test_ca_status_key_usage_bad2(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('cRLSign', True)
        csr.add_extension(ext)

        with self.assertRaises(errors.ValidationError) as e:
            custom.ca_status(
                csr=csr,
                ca_requested=False)
        self.assertEqual("Key usage doesn't match requested CA status "
                         "(keyCertSign/cRLSign: False/True)", str(e.exception))

    def test_ca_status_key_usage_good2(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('cRLSign', True)
        csr.add_extension(ext)

        self.assertEqual(
            None,
            custom.ca_status(
                csr=csr,
                ca_requested=True
            )
        )

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

    def test_csr_signature(self):
        csr = x509_csr.X509Csr.from_buffer(self.csr_sample)
        self.assertEqual(None, custom.csr_signature(csr=csr))

    def test_csr_signature_bad_sig(self):
        csr = x509_csr.X509Csr.from_buffer(self.csr_sample)
        with mock.patch.object(x509_csr.X509Csr, '_get_signature',
                               return_value=(b'A'*49)):
            with self.assertRaisesRegexp(errors.ValidationError,
                                         "Signature on the CSR is not valid"):
                custom.csr_signature(csr=csr)

    def test_csr_signature_bad_algo(self):
        csr = x509_csr.X509Csr.from_buffer(self.csr_sample)
        with mock.patch.object(x509_csr.X509Csr, '_get_signing_algorithm',
                               return_value=rfc2459.id_dsa_with_sha1):
            with self.assertRaisesRegexp(errors.ValidationError,
                                         "Signature on the CSR is not valid"):
                custom.csr_signature(csr=csr)
