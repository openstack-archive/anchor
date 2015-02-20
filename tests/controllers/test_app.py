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

import bad_config_domains
import good_config_domains

from anchor import app


class TestValidDN(unittest.TestCase):

    def setUp(self):
        super(TestValidDN, self).setUp()

    def tearDown(self):
        pass

    def test_self_test(self):
        self.assertTrue(True)

    def test_config_check_domains_good(self):
        self.assertEqual(app.validate_config(good_config_domains), None)

    def test_config_check_domains_bad(self):
        self.assertRaises(
            app.ConfigValidationException,
            app.validate_config,
            bad_config_domains
        )
