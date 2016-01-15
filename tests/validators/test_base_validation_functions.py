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

from anchor.validators import errors
from anchor.validators import utils
from anchor.X509 import name
from anchor.X509 import signing_request
import tests


class TestBaseValidators(tests.DefaultRequestMixin, unittest.TestCase):
    def setUp(self):
        super(TestBaseValidators, self).setUp()
        self.csr = signing_request.X509Csr.from_buffer(
            self.csr_sample_bytes)

    def tearDown(self):
        super(TestBaseValidators, self).tearDown()

    def test_csr_require_cn(self):
        common_name = utils.csr_require_cn(self.csr)
        self.assertEqual(common_name, self.csr_sample_cn)

        self.csr.set_subject(name.X509Name())
        with self.assertRaises(errors.ValidationError):
            utils.csr_require_cn(self.csr)

    def test_check_domains(self):
        test_domain = 'good.example.com'
        test_allowed = ['.example.com', '.example.net']
        self.assertTrue(utils.check_domains(test_domain, test_allowed))
        self.assertFalse(utils.check_domains('bad.example.org',
                                             test_allowed))

    def test_check_networks(self):
        good_ip = netaddr.IPAddress('10.2.3.4')
        bad_ip = netaddr.IPAddress('88.2.3.4')
        test_allowed = ['10/8']
        self.assertTrue(utils.check_networks(good_ip, test_allowed))
        self.assertFalse(utils.check_networks(bad_ip, test_allowed))

    def test_check_networks_invalid(self):
        with self.assertRaises(TypeError):
            utils.check_networks('1.2.3.4', ['10/8'])

    def test_check_networks_passthrough(self):
        good_ip = netaddr.IPAddress('10.2.3.4')
        self.assertTrue(utils.check_networks(good_ip, []))

    def test_check_compare_name_pattern(self):
        cases = [
            ("example.com", "example.com", False, True),
            ("*.example.com", "*.example.com", False, True),
            ("*.example.com", "%.example.com", True, True),
            ("*.example.com", "%.example.com", False, False),
            ("abc.example.com", "%.example.com", False, True),
            ("abc.def.example.com", "%.example.com", False, False),
            ("abc.def.example.com", "%.%.example.com", False, True),
            ("host-123.example.com", "host-%.example.com", False, True),
        ]
        for value, pattern, wildcard, result in cases:
            self.assertEqual(
                result,
                utils.compare_name_pattern(value, pattern, wildcard),
                "checking %s against %s failed" % (value, pattern))
