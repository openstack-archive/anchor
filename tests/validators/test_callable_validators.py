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

from anchor import validators
from anchor.X509 import name as x509_name


class TestValidators(unittest.TestCase):
    def setUp(self):
        super(TestValidators, self).setUp()

    def tearDown(self):
        super(TestValidators, self).tearDown()

    @mock.patch('socket.gethostbyname_ex')
    def test_check_networks_good(self, gethostbyname_ex):
        allowed_networks = ['15/8', '74.125/16']
        gethostbyname_ex.return_value = (
            'example.com',
            [],
            [
                '74.125.224.64',
                '74.125.224.67',
                '74.125.224.68',
                '74.125.224.70',
            ]
        )
        self.assertTrue(validators.check_networks(
            'example.com', allowed_networks))
        self.assertTrue(validators.check_networks_strict(
            'example.com', allowed_networks))

    @mock.patch('socket.gethostbyname_ex')
    def test_check_networks_bad(self, gethostbyname_ex):
        allowed_networks = ['15/8', '74.125/16']
        gethostbyname_ex.return_value = ('example.com', [], ['12.2.2.2'])
        self.assertFalse(validators.check_networks(
            'example.com', allowed_networks))

        gethostbyname_ex.return_value = (
            'example.com',
            ['mock.mock'],
            [
                '15.8.2.2',
                '15.8.2.1',
                '16.1.1.1',
            ]
        )
        self.assertFalse(validators.check_networks_strict(
            'example.com', allowed_networks))

    @mock.patch('socket.gethostbyname_ex')
    def test_check_domains_empty(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('example.com', [], ['12.2.2.2'])
        self.assertTrue(validators.check_domains(
            'example.com', []))

    def test_common_name_with_two_CN(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = "subjectAltName"

        csr_config = {
            'get_extensions.return_value': [ext_mock],
            'get_subject.return_value.get_entries_by_nid_name.return_value':
                ['dummy_value', 'dummy_value'],
        }
        csr_mock = mock.MagicMock(**csr_config)

        with self.assertRaises(validators.ValidationError) as e:
            validators.common_name(
                csr=csr_mock,
                allowed_domains=[],
                allowed_networks=[])
        self.assertEqual("Too many CNs in the request", str(e.exception))

    def test_common_name_no_CN(self):
        csr_config = {
            'get_subject.return_value.__len__.return_value': 0,
            'get_subject.return_value.get_entries_by_nid_name.return_value':
                []
        }
        csr_mock = mock.MagicMock(**csr_config)

        with self.assertRaises(validators.ValidationError) as e:
            validators.common_name(
                csr=csr_mock,
                allowed_domains=[],
                allowed_networks=[])
        self.assertEqual("Alt subjects have to exist if the main subject"
                         " doesn't", str(e.exception))

    @mock.patch('socket.gethostbyname_ex')
    def test_common_name_good_CN(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('master.test.com', [], ['10.0.0.1'])

        cn_mock = mock.MagicMock()
        cn_mock.get_value.return_value = 'master.test.com'

        csr_config = {
            'get_subject.return_value.__len__.return_value': 1,
            'get_subject.return_value.get_entries_by_nid_name.return_value':
                [cn_mock],
        }
        csr_mock = mock.MagicMock(**csr_config)

        self.assertEqual(
            None,
            validators.common_name(
                csr=csr_mock,
                allowed_domains=['.test.com'],
                allowed_networks=['10/8']
            )
        )

    @mock.patch('socket.gethostbyname_ex')
    def test_common_name_bad_CN(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('master.test.com', [], ['10.0.0.1'])

        name = x509_name.X509Name()
        name.add_name_entry('CN', 'test.baddomain.com')

        csr_mock = mock.MagicMock()
        csr_mock.get_subject.return_value = name

        with self.assertRaises(validators.ValidationError) as e:
            validators.common_name(
                csr=csr_mock,
                allowed_domains=['.test.com'],
                allowed_networks=['10/8'])
        self.assertEqual("Domain 'test.baddomain.com' not allowed (does not "
                         "match known domains)", str(e.exception))

    def test_common_name_good_ip_CN(self):
        cn_mock = mock.MagicMock()
        cn_mock.get_value.return_value = '10.0.0.1'

        csr_config = {
            'get_subject.return_value.__len__.return_value': 1,
            'get_subject.return_value.get_entries_by_nid_name.return_value':
                [cn_mock],
        }
        csr_mock = mock.MagicMock(**csr_config)

        self.assertEqual(
            None,
            validators.common_name(
                csr=csr_mock,
                allowed_domains=[],
                allowed_networks=['10/8']
            )
        )

    def test_common_name_bad_ip_CN(self):
        name = x509_name.X509Name()
        name.add_name_entry('CN', '12.0.0.1')

        csr_mock = mock.MagicMock()
        csr_mock.get_subject.return_value = name

        with self.assertRaises(validators.ValidationError) as e:
            validators.common_name(
                csr=csr_mock,
                allowed_domains=[],
                allowed_networks=['10/8'])
        self.assertEqual("Network '12.0.0.1' not allowed (does not match "
                         "known networks)", str(e.exception))

    @mock.patch('socket.gethostbyname_ex')
    def test_alternative_names_good_domain(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('master.test.com', [], ['10.0.0.1'])

        ext_mock = mock.MagicMock()
        ext_mock.get_value.return_value = 'DNS:master.test.com'
        ext_mock.get_name.return_value = 'subjectAltName'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]
        self.assertEqual(
            None,
            validators.alternative_names(
                csr=csr_mock,
                allowed_domains=['.test.com'],
            )
        )

    @mock.patch('socket.gethostbyname_ex')
    def test_alternative_names_bad_domain(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('master.test.com', [], ['10.0.0.1'])

        ext_mock = mock.MagicMock()
        ext_mock.get_value.return_value = 'DNS:test.baddomain.com'
        ext_mock.get_name.return_value = 'subjectAltName'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.alternative_names(
                csr=csr_mock,
                allowed_domains=['.test.com'])
        self.assertEqual("Domain 'test.baddomain.com' not allowed (doesn't "
                         "match known domains or networks)", str(e.exception))

    def test_alternative_names_ext(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_value.return_value = 'BAD,10.1.1.1'
        ext_mock.get_name.return_value = 'subjectAltName'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.alternative_names(
                csr=csr_mock,
                allowed_domains=['.test.com'])
        self.assertEqual("Alt name 'BAD' does not have a known type",
                         str(e.exception))

    @mock.patch('socket.gethostbyname_ex')
    def test_alternative_names_ip_good(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('master.test.com', [], ['10.0.0.1'])

        ext_mock = mock.MagicMock()
        ext_mock.get_value.return_value = 'IP Address:10.1.1.1'
        ext_mock.get_name.return_value = 'subjectAltName'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        self.assertEqual(
            None,
            validators.alternative_names_ip(
                csr=csr_mock,
                allowed_domains=['.test.com'],
                allowed_networks=['10/8']
            )
        )

    @mock.patch('socket.gethostbyname_ex')
    def test_alternative_names_ip_bad(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('master.test.com', [], ['10.0.0.1'])

        ext_mock = mock.MagicMock()
        ext_mock.get_value.return_value = 'IP Address:10.1.1.1'
        ext_mock.get_name.return_value = 'subjectAltName'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.alternative_names_ip(
                csr=csr_mock,
                allowed_domains=['.test.com'],
                allowed_networks=['99/8'])
        self.assertEqual("Domain '10.1.1.1' not allowed (doesn't match known "
                         "domains or networks)", str(e.exception))

    def test_alternative_names_ip_ext(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_value.return_value = 'BAD,10.1.1.1'
        ext_mock.get_name.return_value = 'subjectAltName'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.alternative_names_ip(
                csr=csr_mock,
                allowed_domains=['.test.com'])
        self.assertEqual("Alt name 'BAD' does not have a known type",
                         str(e.exception))

    def test_alternative_names_ip_bad_ext(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_value.return_value = 'BAD:VALUE'
        ext_mock.get_name.return_value = 'subjectAltName'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.alternative_names_ip(
                csr=csr_mock,
                allowed_domains=['.test.com'],
                allowed_networks=['99/8'])
        self.assertEqual("Alt name 'BAD' does not have a known type",
                         str(e.exception))

    def test_server_group_no_prefix1(self):
        cn_mock = mock.MagicMock()
        cn_mock.get_value.return_value = 'master.test.com'

        csr_config = {
            'get_subject.return_value.get_entries_by_nid_name.return_value':
                [cn_mock],
        }
        csr_mock = mock.MagicMock(**csr_config)

        self.assertEqual(
            None,
            validators.server_group(
                auth_result=None,
                csr=csr_mock,
                group_prefixes={}
            )
        )

    def test_server_group_no_prefix2(self):
        cn_mock = mock.MagicMock()
        cn_mock.get_value.return_value = 'nv_master.test.com'

        csr_config = {
            'get_subject.return_value.get_entries_by_nid_name.return_value':
                [cn_mock],
        }
        csr_mock = mock.MagicMock(**csr_config)

        self.assertEqual(
            None,
            validators.server_group(
                auth_result=None,
                csr=csr_mock,
                group_prefixes={}
            )
        )

    def test_server_group_good_prefix(self):
        # 'nv' in prefix means only Nova members should be able to issue
        auth_result = mock.Mock()
        auth_result.groups = ['nova']

        cn_mock = mock.MagicMock()
        cn_mock.get_value.return_value = 'nv_master.test.com'

        csr_config = {
            'get_subject.return_value.get_entries_by_nid_name.return_value':
                [cn_mock],
        }
        csr_mock = mock.MagicMock(**csr_config)

        self.assertEqual(
            None,
            validators.server_group(
                auth_result=auth_result,
                csr=csr_mock,
                group_prefixes={'nv': 'nova', 'sw': 'swift'}
            )
        )

    def test_server_group_bad(self):
        auth_result = mock.Mock()
        auth_result.groups = ['glance']

        cn_mock = mock.MagicMock()
        cn_mock.get_value.return_value = 'nv-master.test.com'

        csr_config = {
            'get_subject.return_value.get_entries_by_nid_name.return_value':
                [cn_mock],
        }
        csr_mock = mock.MagicMock(**csr_config)

        with self.assertRaises(validators.ValidationError) as e:
            validators.server_group(
                auth_result=auth_result,
                csr=csr_mock,
                group_prefixes={'nv': 'nova', 'sw': 'swift'})
        self.assertEqual("Server prefix doesn't match user groups",
                         str(e.exception))

    def test_extensions_bad(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'BAD'
        ext_mock.get_value.return_value = 'BAD'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.extensions(
                csr=csr_mock,
                allowed_extensions=['GOOD-1', 'GOOD-2'])
        self.assertEqual("Extension 'BAD' not allowed", str(e.exception))

    def test_extensions_good(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'GOOD-1'
        ext_mock.get_value.return_value = 'GOOD-1'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        self.assertEqual(
            None,
            validators.extensions(
                csr=csr_mock,
                allowed_extensions=['GOOD-1', 'GOOD-2']
            )
        )

    def test_key_usage_bad(self):
        allowed_usage = ['Digital Signature',
                         'Non Repudiation',
                         'Key Encipherment']

        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'keyUsage'
        ext_mock.get_value.return_value = 'Domination'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.key_usage(
                csr=csr_mock,
                allowed_usage=allowed_usage)
        self.assertEqual("Found some not allowed key usages: "
                         "set(['Domination'])", str(e.exception))

    def test_key_usage_good(self):
        allowed_usage = ['Digital Signature',
                         'Non Repudiation',
                         'Key Encipherment']

        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'keyUsage'
        ext_mock.get_value.return_value = 'Key Encipherment, Digital Signature'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        self.assertEqual(
            None,
            validators.key_usage(
                csr=csr_mock,
                allowed_usage=allowed_usage
            )
        )

    def test_ca_status_good1(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'basicConstraints'
        ext_mock.get_value.return_value = 'CA:TRUE'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        self.assertEqual(
            None,
            validators.ca_status(
                csr=csr_mock,
                ca_requested=True
            )
        )

    def test_ca_status_good2(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'basicConstraints'
        ext_mock.get_value.return_value = 'CA:FALSE'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        self.assertEqual(
            None,
            validators.ca_status(
                csr=csr_mock,
                ca_requested=False
            )
        )

    def test_ca_status_bad(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'basicConstraints'
        ext_mock.get_value.return_value = 'CA:FALSE'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.ca_status(
                csr=csr_mock,
                ca_requested=True)
        self.assertEqual("Invalid CA status, 'CA:FALSE' requested",
                         str(e.exception))

    def test_ca_status_bad_format1(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'basicConstraints'
        ext_mock.get_value.return_value = 'CA~FALSE'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.ca_status(
                csr=csr_mock,
                ca_requested=False)
        self.assertEqual("Invalid basic constraints flag", str(e.exception))

    def test_ca_status_bad_format2(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'basicConstraints'
        ext_mock.get_value.return_value = 'CA:FALSE:DERP'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.ca_status(
                csr=csr_mock,
                ca_requested=False)
        self.assertEqual("Invalid basic constraints flag", str(e.exception))

    def test_ca_status_pathlen(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'basicConstraints'
        ext_mock.get_value.return_value = 'pathlen:somthing'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        self.assertEqual(
            None,
            validators.ca_status(
                csr=csr_mock,
                ca_requested=False
            )
        )

    def test_ca_status_bad_value(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'basicConstraints'
        ext_mock.get_value.return_value = 'BAD:VALUE'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.ca_status(
                csr=csr_mock,
                ca_requested=False)
        self.assertEqual("Invalid basic constraints option", str(e.exception))

    def test_ca_status_key_usage_bad1(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'keyUsage'
        ext_mock.get_value.return_value = 'Certificate Sign'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.ca_status(
                csr=csr_mock,
                ca_requested=False)
        self.assertEqual("Key usage doesn't match requested CA status "
                         "(keyCertSign/cRLSign: True/False)", str(e.exception))

    def test_ca_status_key_usage_good1(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'keyUsage'
        ext_mock.get_value.return_value = 'Certificate Sign'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.ca_status(
                csr=csr_mock,
                ca_requested=True)
        self.assertEqual("Key usage doesn't match requested CA status "
                         "(keyCertSign/cRLSign: True/False)", str(e.exception))

    def test_ca_status_key_usage_bad2(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'keyUsage'
        ext_mock.get_value.return_value = 'CRL Sign'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.ca_status(
                csr=csr_mock,
                ca_requested=False)
        self.assertEqual("Key usage doesn't match requested CA status "
                         "(keyCertSign/cRLSign: False/True)", str(e.exception))

    def test_ca_status_key_usage_good2(self):
        ext_mock = mock.MagicMock()
        ext_mock.get_name.return_value = 'keyUsage'
        ext_mock.get_value.return_value = 'CRL Sign'

        csr_mock = mock.MagicMock()
        csr_mock.get_extensions.return_value = [ext_mock]

        with self.assertRaises(validators.ValidationError) as e:
            validators.ca_status(
                csr=csr_mock,
                ca_requested=True)
        self.assertEqual("Key usage doesn't match requested CA status "
                         "(keyCertSign/cRLSign: False/True)", str(e.exception))

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
