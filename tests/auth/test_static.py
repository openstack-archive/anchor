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

import unittest

import mock
from webob import exc as http_status

from anchor import auth
from anchor.auth import results
from anchor import jsonloader
import tests


class AuthStaticTests(tests.DefaultConfigMixin, unittest.TestCase):

    def setUp(self):
        super(AuthStaticTests, self).setUp()

    def tearDown(self):
        pass

    def test_validate_static(self):
        """Test all static user/pass authentication paths."""
        jsonloader.conf.load_extensions()
        config = "anchor.jsonloader.conf._config"
        self.sample_conf_auth['default_auth'] = {
            "backend": "static",
            "user": "myusername",
            "secret": "simplepassword"
        }
        data = self.sample_conf

        with mock.patch.dict(config, data):
            valid_user = self.sample_conf_auth['default_auth']['user']
            valid_pass = self.sample_conf_auth['default_auth']['secret']

            expected = results.AuthDetails(username=valid_user, groups=[])
            self.assertEqual(auth.validate('default_ra', valid_user,
                                           valid_pass), expected)
            with self.assertRaises(http_status.HTTPUnauthorized):
                auth.validate('default_ra', valid_user, 'badpass')
            with self.assertRaises(http_status.HTTPUnauthorized):
                auth.validate('default_ra', 'baduser', valid_pass)
            with self.assertRaises(http_status.HTTPUnauthorized):
                auth.validate('default_ra', 'baduser', 'badpass')

    def test_validate_static_malformed1(self):
        """Test static user/pass authentication with malformed config."""
        jsonloader.conf.load_extensions()
        config = "anchor.jsonloader.conf._config"
        self.sample_conf_auth['default_auth'] = {'backend': 'static'}
        data = self.sample_conf

        with mock.patch.dict(config, data):
            with self.assertRaises(http_status.HTTPUnauthorized):
                auth.validate('default_ra', 'baduser', 'badpass')
