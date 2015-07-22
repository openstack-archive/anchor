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

from anchor.X509 import utils


class TestASN1Time(unittest.TestCase):
    def test_round_check(self):
        t = 0
        asn1_time = utils.timestamp_to_asn1_time(t)
        res = utils.asn1_time_to_timestamp(asn1_time)
        self.assertEqual(t, res)

    def test_post_2050(self):
        """Test date post 2050, which causes different encoding."""
        t = 2600000000
        asn1_time = utils.timestamp_to_asn1_time(t)
        res = utils.asn1_time_to_timestamp(asn1_time)
        self.assertEqual(t, res)
