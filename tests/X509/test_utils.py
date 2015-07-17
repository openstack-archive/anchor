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

import datetime
import unittest

import mock

from anchor.X509 import errors
from anchor.X509 import utils

from cryptography.hazmat.backends.openssl import backend


class TestASN1String(unittest.TestCase):
    # missing in cryptography.io
    V_ASN1_UTF8STRING = 12

    def test_utf8_string(self):
        orig = u"test \u2603 snowman"
        encoded = orig.encode('utf-8')
        asn1string = backend._lib.ASN1_STRING_type_new(self.V_ASN1_UTF8STRING)
        backend._lib.ASN1_STRING_set(asn1string, encoded, len(encoded))

        res = utils.asn1_string_to_utf8(asn1string)
        self.assertEqual(res, orig)

    def test_invalid_string(self):
        encoded = b"\xff"
        asn1string = backend._lib.ASN1_STRING_type_new(self.V_ASN1_UTF8STRING)
        backend._lib.ASN1_STRING_set(asn1string, encoded, len(encoded))

        self.assertRaises(errors.ASN1StringError, utils.asn1_string_to_utf8,
                          asn1string)


class TestASN1Time(unittest.TestCase):
    def test_conversion_failure(self):
        with mock.patch.object(backend._lib, "ASN1_TIME_to_generalizedtime",
                               return_value=backend._ffi.NULL):
            t = utils.timestamp_to_asn1_time(0)
            self.assertRaises(errors.ASN1TimeError,
                              utils.asn1_time_to_timestamp, t)

    def test_generalizedtime_check_failure(self):
        with mock.patch.object(backend._lib, "ASN1_GENERALIZEDTIME_check",
                               return_value=0):
            self.assertRaises(errors.ASN1TimeError,
                              utils.timestamp_to_asn1_time, 0)


class TestTimezone(unittest.TestCase):
    def test_utcoffset(self):
        tz = utils.create_timezone(1234)
        offset = tz.utcoffset(datetime.datetime.now())
        self.assertEqual(datetime.timedelta(minutes=1234), offset)

    def test_dst(self):
        tz = utils.create_timezone(1234)
        offset = tz.dst(datetime.datetime.now())
        self.assertEqual(datetime.timedelta(0), offset)

    def test_name(self):
        tz = utils.create_timezone(1234)
        name = tz.tzname(datetime.datetime.now())
        self.assertIsNone(name)

    def test_repr(self):
        tz = utils.create_timezone(1234)
        self.assertEqual("Timezone +2034", repr(tz))
