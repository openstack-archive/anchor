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
import mock

from anchor import util


class UtilTests(unittest.TestCase):

    @mock.patch('hmac.compare_digest')
    def test_compare_with_hmac(self, compare_digest):
        compare_digest.return_value = True
        self.assertTrue(util.constant_time_compare("", ""))

    @mock.patch('hmac.compare_digest')
    def test_compare_with_shim_eq(self, compare_digest):
        compare_digest.side_effect = AttributeError(
            "'hmac' has no attribute 'compare_digest'")
        self.assertTrue(util.constant_time_compare("abc", "abc"))

    @mock.patch('hmac.compare_digest')
    def test_compare_with_shim_ne(self, compare_digest):
        compare_digest.side_effect = AttributeError(
            "'hmac' has no attribute 'compare_digest'")
        self.assertFalse(util.constant_time_compare("abc", "def"))

    @mock.patch('hmac.compare_digest')
    def test_compare_with_shim_different_len(self, compare_digest):
        compare_digest.side_effect = AttributeError(
            "'hmac' has no attribute 'compare_digest'")
        self.assertFalse(util.constant_time_compare("abc", ""))
