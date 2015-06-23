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
