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

import os

import unittest
import base64

from anchor.X509 import message_digest


class TestMessageDigest(unittest.TestCase):
    data = "this is test data to test with"

    def setUp(self):
        super(TestMessageDigest, self).setUp()

    def tearDown(self):
        super(TestMessageDigest, self).tearDown()

    def test_bad_algo(self):
        self.assertRaises(message_digest.MessageDigestError,
                          message_digest.MessageDigest,
                          'BAD')

    def test_md5(self):
        v = "B2F81E9F287884AF6A8B3E8EFB96C711"
        md = message_digest.MessageDigest("md5")
        md.update(TestMessageDigest.data)
        ret = md.final()
        self.assertEqual(ret, v)

    def test_ripmed160(self):
        v = "BA5CCC4574D676266D821269CA77BFFD7FD9FCB0"
        md = message_digest.MessageDigest("ripemd160")
        md.update(TestMessageDigest.data)
        ret = md.final()
        self.assertEqual(ret, v)

    def test_sha224(self):
        v = "675170C12E88D549DB0F608AD6857103D7B792F29FACFCC53173F178"
        md = message_digest.MessageDigest("sha224")
        md.update(TestMessageDigest.data)
        ret = md.final()
        self.assertEqual(ret, v)

    def test_sha256(self):
        v = "91F672E796E84BECC6F051A47D7392BD789AEA7D55090588F212CF041C862678"
        md = message_digest.MessageDigest("sha256")
        md.update(TestMessageDigest.data)
        ret = md.final()
        self.assertEqual(ret, v)

    def test_sha384(self):
        v = ("9667AF42DF2E6B81EE679757BB207A3F9BB7CED49CF838FF3ED8237C9B15291B"
             "15")
        md = message_digest.MessageDigest("sha384")
        md.update(TestMessageDigest.data)
        ret = md.final()
        self.assertEqual(ret, v)

    def test_sha512(self):
        v = ("283B3ECD8AE687226C3EA46B59F65E5CA50A11735C9C14BED11F0CCB515707B5"
             "1031145ED8AE4B35B24B91F26E70AC0ACAC37B5BEE933B28834FE6447D1298CB"
             )
        md = message_digest.MessageDigest("sha512")
        md.update(TestMessageDigest.data)
        ret = md.final()
        self.assertEqual(ret, v)
