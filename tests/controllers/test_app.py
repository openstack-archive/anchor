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


import json
import stat
import unittest

import mock

from anchor import app
from anchor import errors
from anchor import jsonloader
from anchor import util
import tests


class TestApp(tests.DefaultConfigMixin, unittest.TestCase):
    def setUp(self):
        self.expected_key_permissions = (stat.S_IRUSR | stat.S_IFREG)
        jsonloader.conf.load_extensions()
        super(TestApp, self).setUp()

    def tearDown(self):
        jsonloader.conf._config = {}
        super(TestApp, self).tearDown()

    def test_self_test(self):
        self.assertTrue(True)

    @mock.patch('anchor.util.check_file_exists')
    @mock.patch('anchor.util.check_file_permissions')
    def test_config_check_domains_good(self, a, b):
        self.sample_conf_ra['default_ra']['validators'] = {
            "common_name": {
                "allowed_domains": [".example.com"]
            }
        }
        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)

        config = {'return_value.st_mode': (stat.S_IRUSR | stat.S_IFREG)}
        with mock.patch("os.stat", **config):
            self.assertEqual(app.validate_config(jsonloader.conf), None)

    @mock.patch('anchor.util.check_file_exists')
    @mock.patch('anchor.util.check_file_permissions')
    def test_config_check_domains_bad(self, a, b):
        self.sample_conf_ra['default_ra']['validators'] = {
            "common_name": {
                "allowed_domains": ["error.example.com"]
            }
        }
        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)

        config = {'return_value.st_mode': (stat.S_IRUSR | stat.S_IFREG)}
        with mock.patch("os.stat", **config):
            self.assertRaises(
                errors.ConfigValidationException,
                app.validate_config,
                jsonloader.conf
            )

    def test_check_file_permissions_good(self):
        config = {'return_value.st_mode': (stat.S_IRUSR | stat.S_IFREG)}
        with mock.patch("os.stat", **config):
            util.check_file_permissions("/mock/path")

    def test_check_file_permissions_bad(self):
        config = {'return_value.st_mode': (stat.S_IWOTH | stat.S_IFREG)}
        with mock.patch("os.stat", **config):
            self.assertRaises(errors.ConfigValidationException,
                              util.check_file_permissions, "/mock/path")

    def test_validate_old_config(self):
        config = json.dumps({
            "ca": {},
            "auth": {},
            "validators": {},
        })
        jsonloader.conf.load_str_data(config)
        self.assertRaisesRegexp(errors.ConfigValidationException,
                                "old version of Anchor",
                                app.validate_config, jsonloader.conf)

    @mock.patch('anchor.util.check_file_permissions')
    def test_validate_config_no_registration_authorities(self,
                                                         mock_check_perm):
        del self.sample_conf['registration_authority']
        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)
        self.assertRaisesRegexp(errors.ConfigValidationException,
                                "No registration authorities present",
                                app.validate_config, jsonloader.conf)

    @mock.patch('anchor.util.check_file_permissions')
    def test_validate_config_no_auth(self, mock_check_perm):
        del self.sample_conf['authentication']
        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)
        self.assertRaisesRegexp(errors.ConfigValidationException,
                                "No authentication methods present",
                                app.validate_config, jsonloader.conf)

    @mock.patch('anchor.util.check_file_permissions')
    def test_validate_config_no_auth_backend(self, mock_check_perm):
        del self.sample_conf_auth['default_auth']['backend']
        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)
        self.assertRaisesRegexp(errors.ConfigValidationException,
                                "Authentication method .* doesn't define "
                                "backend",
                                app.validate_config, jsonloader.conf)

    @mock.patch('anchor.util.check_file_permissions')
    def test_validate_config_no_ra_auth(self, mock_check_perm):
        del self.sample_conf_ra['default_ra']['authentication']
        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)
        self.assertRaisesRegexp(errors.ConfigValidationException,
                                "No authentication .* for .* default_ra",
                                app.validate_config, jsonloader.conf)

    def test_validate_config_no_ca(self):
        del self.sample_conf['signing_ca']
        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)
        self.assertRaisesRegexp(errors.ConfigValidationException,
                                "No signing CA configurations present",
                                app.validate_config, jsonloader.conf)

    @mock.patch('anchor.util.check_file_permissions')
    def test_validate_config_no_ra_ca(self, mock_check_perm):
        del self.sample_conf_ra['default_ra']['signing_ca']
        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)
        self.assertRaisesRegexp(errors.ConfigValidationException,
                                "No signing CA .* for .* default_ra",
                                app.validate_config, jsonloader.conf)

    @mock.patch('anchor.util.check_file_permissions')
    def test_validate_config_ca_config_reqs(self, mock_check_perm):
        ca_config_requirements = ["cert_path", "key_path", "output_path",
                                  "signing_hash", "valid_hours"]

        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)

        # Iterate through the ca_config_requirements, replace each one in turn
        # with 'missing_req', perform validation. Each should raise in turn
        for req in ca_config_requirements:
            jsonloader.conf.load_str_data(config.replace(req, "missing_req"))
            self.assertRaisesRegexp(errors.ConfigValidationException,
                                    "CA config missing: %s" % req,
                                    app.validate_config, jsonloader.conf)

    @mock.patch('os.path.isfile')
    def test_validate_config_no_ca_cert_file(self, isfile):
        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)
        isfile.return_value = False
        self.assertRaisesRegexp(errors.ConfigValidationException,
                                "could not read file: tests/CA/root-ca.crt",
                                app.validate_config, jsonloader.conf)

    @mock.patch('anchor.util.check_file_permissions')
    @mock.patch('os.path.isfile')
    @mock.patch('os.access')
    @mock.patch('os.stat')
    def test_validate_config_no_validators(self, stat, access, isfile,
                                           mock_check_perm):
        self.sample_conf_ra['default_ra']['validators'] = {}
        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)
        isfile.return_value = True
        access.return_value = True
        stat.return_value.st_mode = self.expected_key_permissions
        self.assertRaisesRegexp(errors.ConfigValidationException,
                                "No validators configured",
                                app.validate_config, jsonloader.conf)

    @mock.patch('anchor.util.check_file_permissions')
    @mock.patch('os.path.isfile')
    @mock.patch('os.access')
    @mock.patch('os.stat')
    def test_validate_config_unknown_validator(self, stat, access, isfile,
                                               mock_check_perm):
        self.sample_conf_validators['unknown_validator'] = {}
        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)
        isfile.return_value = True
        access.return_value = True
        stat.return_value.st_mode = self.expected_key_permissions
        with self.assertRaises(errors.ConfigValidationException,
                               msg="Unknown validator <unknown_validator> "
                                   "found (for registration authority "
                                   "default)"):
            app.validate_config(jsonloader.conf)

    @mock.patch('anchor.util.check_file_permissions')
    @mock.patch('os.path.isfile')
    @mock.patch('os.access')
    @mock.patch('os.stat')
    def test_validate_config_good(self, stat, access, isfile, mock_check_perm):
        config = json.dumps(self.sample_conf)
        jsonloader.conf.load_str_data(config)
        isfile.return_value = True
        access.return_value = True
        stat.return_value.st_mode = self.expected_key_permissions
        app.validate_config(jsonloader.conf)

    @mock.patch('anchor.jsonloader.conf.load_file_data')
    def test_config_paths_env(self, conf):
        with mock.patch.dict('os.environ', {'ANCHOR_CONF': '/fake/fake'}):
            app.load_config()
            conf.assert_called_with('/fake/fake')

    @mock.patch('anchor.jsonloader.conf.load_file_data')
    def test_config_paths_local(self, conf):
        ret = lambda x: True if x == 'config.json' else False
        with mock.patch("os.path.isfile", ret):
            app.load_config()
            conf.assert_called_with('config.json')

    @mock.patch('anchor.jsonloader.conf.load_file_data')
    def test_config_paths_user(self, conf):
        ret = (lambda x: True if x == '/fake/.config/anchor/config.json'
               else False)
        with mock.patch('os.path.isfile', ret):
            with mock.patch.dict('os.environ', {'HOME': '/fake'}):
                app.load_config()
                conf.assert_called_with('/fake/.config/anchor/config.json')

    @mock.patch('anchor.jsonloader.conf.load_file_data')
    def test_config_paths_system(self, conf):
        ret = lambda x: True if x == '/etc/anchor/config.json' else False
        with mock.patch('os.path.isfile', ret):
            app.load_config()
            conf.assert_called_with('/etc/anchor/config.json')
