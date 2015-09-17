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

import ldap3
import mock
from webob import exc as http_status

from anchor import auth
from anchor.auth import results
from anchor import jsonloader
import tests


class AuthLdapTests(tests.DefaultConfigMixin, unittest.TestCase):

    def setUp(self):
        super(AuthLdapTests, self).setUp()
        self.sample_conf_auth['default_auth'] = {
            "backend": "ldap",
            "host": "ldap.example.com",
            "base": "CN=Users,DC=example,DC=com",
            "domain": "example.com",
            "port": 636,
            "ssl": True
        }

    def tearDown(self):
        pass

    @mock.patch('ldap3.Connection')
    def test_login_good(self, mock_connection):
        """Test all static user/pass authentication paths."""
        jsonloader.conf.load_extensions()
        config = "anchor.jsonloader.conf._config"

        mock_ldc = mock.Mock()
        mock_connection.return_value = mock_ldc
        mock_ldc.result = {'result': 0}
        mock_ldc.response = [{'attributes': {}}]

        with mock.patch.dict(config, self.sample_conf):
            expected = results.AuthDetails(username='user', groups=[])
            self.assertEqual(auth.validate('default_ra', 'user', 'pass'),
                             expected)

    @mock.patch('ldap3.Connection')
    def test_login_good_with_groups(self, mock_connection):
        """Test all static user/pass authentication paths."""
        jsonloader.conf.load_extensions()
        config = "anchor.jsonloader.conf._config"

        mock_ldc = mock.Mock()
        mock_connection.return_value = mock_ldc
        mock_ldc.result = {'result': 0}
        mock_ldc.response = [{'attributes': {'memberOf': [
            u'CN=some_group,OU=Groups,DC=example,DC=com',
            u'CN=other_group,OU=Groups,DC=example,DC=com']}}]

        with mock.patch.dict(config, self.sample_conf):
            expected = results.AuthDetails(
                username='user',
                groups=[u'some_group', u'other_group'])
            self.assertEqual(auth.validate('default_ra', 'user', 'pass'),
                             expected)

    @mock.patch('ldap3.Connection')
    def test_login_search_fail(self, mock_connection):
        """Test all static user/pass authentication paths."""
        jsonloader.conf.load_extensions()
        config = "anchor.jsonloader.conf._config"

        mock_ldc = mock.Mock()
        mock_connection.return_value = mock_ldc
        mock_ldc.result = {'result': 1}

        with mock.patch.dict(config, self.sample_conf):
            with self.assertRaises(http_status.HTTPUnauthorized):
                auth.validate('default_ra', 'user', 'pass')

    @mock.patch('ldap3.Connection')
    def test_login_bind_fail(self, mock_connection):
        """Test all static user/pass authentication paths."""
        jsonloader.conf.load_extensions()
        config = "anchor.jsonloader.conf._config"

        mock_connection.side_effect = ldap3.LDAPBindError()

        with mock.patch.dict(config, self.sample_conf):
            with self.assertRaises(http_status.HTTPUnauthorized):
                auth.validate('default_ra', 'user', 'pass')

    @mock.patch('ldap3.Connection')
    def test_login_connection_fail(self, mock_connection):
        """Test all static user/pass authentication paths."""
        jsonloader.conf.load_extensions()
        config = "anchor.jsonloader.conf._config"

        mock_connection.side_effect = ldap3.LDAPSocketOpenError()

        with mock.patch.dict(config, self.sample_conf):
            with self.assertRaises(http_status.HTTPUnauthorized):
                auth.validate('default_ra', 'user', 'pass')
