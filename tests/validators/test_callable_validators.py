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

from anchor import validators
from anchor.X509 import extension as x509_ext
from anchor.X509 import name as x509_name
from anchor.X509 import signing_request as x509_csr


class TestValidators(unittest.TestCase):
    def setUp(self):
        super(TestValidators, self).setUp()

    def tearDown(self):
        super(TestValidators, self).tearDown()

    def test_check_networks_good(self):
        allowed_networks = ['15/8', '74.125/16']
        self.assertTrue(validators.check_networks(
            netaddr.IPAddress('74.125.224.64'), allowed_networks))

    def test_check_networks_bad(self):
        allowed_networks = ['15/8', '74.125/16']
        self.assertFalse(validators.check_networks(
            netaddr.IPAddress('12.2.2.2'), allowed_networks))

    def test_check_domains_empty(self):
        self.assertTrue(validators.check_domains(
            'example.com', []))

    def test_common_name_with_two_CN(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, "dummy_value")
        name.add_name_entry(x509_name.OID_commonName, "dummy_value")

        with self.assertRaises(validators.ValidationError) as e:
            validators.common_name(
                csr=csr,
                allowed_domains=[],
                allowed_networks=[])
        self.assertEqual("Too many CNs in the request", str(e.exception))

    def test_common_name_no_CN(self):
        csr = x509_csr.X509Csr()

        with self.assertRaises(validators.ValidationError) as e:
            validators.common_name(
                csr=csr,
                allowed_domains=[],
                allowed_networks=[])
        self.assertEqual("Alt subjects have to exist if the main subject"
                         " doesn't", str(e.exception))

    def test_common_name_good_CN(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, "master.test.com")

        self.assertEqual(
            None,
            validators.common_name(
                csr=csr,
                allowed_domains=['.test.com'],
            )
        )

    def test_common_name_bad_CN(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, 'test.baddomain.com')

        with self.assertRaises(validators.ValidationError) as e:
            validators.common_name(
                csr=csr,
                allowed_domains=['.test.com'])
        self.assertEqual("Domain 'test.baddomain.com' not allowed (does not "
                         "match known domains)", str(e.exception))

    def test_common_name_ip_good(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, '10.1.1.1')

        self.assertEqual(
            None,
            validators.common_name(
                csr=csr,
                allowed_domains=['.test.com'],
                allowed_networks=['10/8']
            )
        )

    def test_common_name_ip_bad(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, '15.1.1.1')

        with self.assertRaises(validators.ValidationError) as e:
            validators.common_name(
                csr=csr,
                allowed_domains=['.test.com'],
                allowed_networks=['10/8'])
        self.assertEqual("Address '15.1.1.1' not allowed (does not "
                         "match known networks)", str(e.exception))

    def test_alternative_names_good_domain(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('master.test.com')
        csr.add_extension(ext)

        self.assertEqual(
            None,
            validators.alternative_names(
                csr=csr,
                allowed_domains=['.test.com'],
            )
        )

    def test_alternative_names_bad_domain(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('test.baddomain.com')
        csr.add_extension(ext)

        with self.assertRaises(validators.ValidationError) as e:
            validators.alternative_names(
                csr=csr,
                allowed_domains=['.test.com'])
        self.assertEqual("Domain 'test.baddomain.com' not allowed (doesn't "
                         "match known domains)", str(e.exception))

    def test_alternative_names_ip_good(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_ip(netaddr.IPAddress('10.1.1.1'))
        csr.add_extension(ext)

        self.assertEqual(
            None,
            validators.alternative_names_ip(
                csr=csr,
                allowed_domains=['.test.com'],
                allowed_networks=['10/8']
            )
        )

    def test_alternative_names_ip_bad(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_ip(netaddr.IPAddress('10.1.1.1'))
        csr.add_extension(ext)

        with self.assertRaises(validators.ValidationError) as e:
            validators.alternative_names_ip(
                csr=csr,
                allowed_domains=['.test.com'],
                allowed_networks=['99/8'])
        self.assertEqual("IP '10.1.1.1' not allowed (doesn't match known "
                         "networks)", str(e.exception))

    def test_alternative_names_ip_bad_domain(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('test.baddomain.com')
        csr.add_extension(ext)

        with self.assertRaises(validators.ValidationError) as e:
            validators.alternative_names_ip(
                csr=csr,
                allowed_domains=['.test.com'])
        self.assertEqual("Domain 'test.baddomain.com' not allowed (doesn't "
                         "match known domains)", str(e.exception))

    def test_server_group_no_prefix1(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, "master.test.com")

        self.assertEqual(
            None,
            validators.server_group(
                auth_result=None,
                csr=csr,
                group_prefixes={}
            )
        )

    def test_server_group_no_prefix2(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, "nv_master.test.com")

        self.assertEqual(
            None,
            validators.server_group(
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
        name.add_name_entry(x509_name.OID_commonName, "nv_master.test.com")

        self.assertEqual(
            None,
            validators.server_group(
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
        name.add_name_entry(x509_name.OID_commonName, "nv-master.test.com")

        with self.assertRaises(validators.ValidationError) as e:
            validators.server_group(
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

        with self.assertRaises(validators.ValidationError) as e:
            validators.extensions(
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
            validators.extensions(
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
            validators.extensions(
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

        with self.assertRaises(validators.ValidationError) as e:
            validators.key_usage(
                csr=csr,
                allowed_usage=allowed_usage)
        self.assertEqual("Found some not allowed key usages: "
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
            validators.key_usage(
                csr=csr,
                allowed_usage=allowed_usage
            )
        )

    def test_ca_status_good1(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionBasicConstraints()
        ext.set_ca(True)
        csr.add_extension(ext)

        self.assertEqual(
            None,
            validators.ca_status(
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
            validators.ca_status(
                csr=csr,
                ca_requested=False
            )
        )

    def test_ca_status_forbidden(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionBasicConstraints()
        ext.set_ca(True)
        csr.add_extension(ext)

        with self.assertRaises(validators.ValidationError) as e:
            validators.ca_status(
                csr=csr,
                ca_requested=False)
        self.assertEqual("CA status requested, but not allowed",
                         str(e.exception))

    def test_ca_status_bad(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionBasicConstraints()
        ext.set_ca(False)
        csr.add_extension(ext)

        with self.assertRaises(validators.ValidationError) as e:
            validators.ca_status(
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
            validators.ca_status(
                csr=csr,
                ca_requested=False
            )
        )

    def test_ca_status_key_usage_bad1(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('keyCertSign', True)
        csr.add_extension(ext)

        with self.assertRaises(validators.ValidationError) as e:
            validators.ca_status(
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
            validators.ca_status(
                csr=csr,
                ca_requested=True
            )
        )

    def test_ca_status_key_usage_bad2(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionKeyUsage()
        ext.set_usage('cRLSign', True)
        csr.add_extension(ext)

        with self.assertRaises(validators.ValidationError) as e:
            validators.ca_status(
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
            validators.ca_status(
                csr=csr,
                ca_requested=True
            )
        )

    def test_source_cidrs_good(self):
        request = mock.Mock(client_addr='127.0.0.1')
        self.assertEqual(
            None,
            validators.source_cidrs(
                request=request,
                cidrs=['127/8', '10/8']
            )
        )

    def test_source_cidrs_out_of_range(self):
        request = mock.Mock(client_addr='99.0.0.1')
        with self.assertRaises(validators.ValidationError) as e:
            validators.source_cidrs(
                request=request,
                cidrs=['127/8', '10/8'])
        self.assertEqual("No network matched the request source '99.0.0.1'",
                         str(e.exception))

    def test_source_cidrs_bad_cidr(self):
        request = mock.Mock(client_addr='127.0.0.1')
        with self.assertRaises(validators.ValidationError) as e:
            validators.source_cidrs(
                request=request,
                cidrs=['bad'])
        self.assertEqual("Cidr 'bad' does not describe a valid network",
                         str(e.exception))

    def test_blacklist_names_good(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('blah.good')
        csr.add_extension(ext)

        self.assertEqual(
            None,
            validators.blacklist_names(
                csr=csr,
                domains=['.bad'],
            )
        )

    def test_blacklist_names_bad(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('blah.bad')
        csr.add_extension(ext)

        with self.assertRaises(validators.ValidationError):
            validators.blacklist_names(
                csr=csr,
                domains=['.bad'],
            )

    def test_blacklist_names_bad_cn(self):
        csr = x509_csr.X509Csr()
        name = csr.get_subject()
        name.add_name_entry(x509_name.OID_commonName, "blah.bad")

        with self.assertRaises(validators.ValidationError):
            validators.blacklist_names(
                csr=csr,
                domains=['.bad'],
            )

    def test_blacklist_names_mix(self):
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('blah.bad')
        ext.add_dns_id('blah.good')
        csr.add_extension(ext)

        with self.assertRaises(validators.ValidationError):
            validators.blacklist_names(
                csr=csr,
                domains=['.bad'],
            )

    def test_blacklist_names_empty_list(self):
        # empty blacklist should pass everything through
        csr = x509_csr.X509Csr()
        ext = x509_ext.X509ExtensionSubjectAltName()
        ext.add_dns_id('blah.good')
        csr.add_extension(ext)

        self.assertEqual(
            None,
            validators.blacklist_names(
                csr=csr,
            )
        )
