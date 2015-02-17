# -*- coding:utf-8 -*-
#
# Copyright 2015 Nebula Inc.
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
import mock
import unittest

from pecan import conf


class AuthInitTests(unittest.TestCase):

    def setUp(self):
        super(AuthInitTests, self).setUp()

    def tearDown(self):
        pass

    def test_validate_static(self):
        """Test all static user/pass authentication paths.
        """
        config = 'pecan.conf.__values__'
        data = {'auth': {'static': {'secret': 'simplepassword',
                                    'user': 'myusername'},
                        }
               }
        with mock.patch.dict(config, data):
            # can't import until mock'd
            from anchor import auth
            from anchor.auth.results import AUTH_FAILED
            from anchor.auth.results import AuthDetails

            valid_user = data['auth']['static']['user']
            valid_pass = data['auth']['static']['secret']

            expected = AuthDetails(username=valid_user, groups=[])
            self.assertEqual(auth.validate(valid_user, valid_pass), expected)
            self.assertEqual(auth.validate(valid_user, 'badpass'), AUTH_FAILED)
            self.assertEqual(auth.validate('baduser', valid_pass), AUTH_FAILED)
            self.assertEqual(auth.validate('baduser', 'badpass'), AUTH_FAILED)
