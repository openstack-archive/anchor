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

import copy
import json
import os
import stat
import tempfile
import unittest

import mock
import pecan
from pecan import testing as pecan_testing
import stevedore

from anchor import jsonloader
from anchor.X509 import certificate as X509_cert
import config
import tests


class TestFunctional(tests.DefaultConfigMixin, tests.DefaultRequestMixin,
                     unittest.TestCase):
    def setUp(self):
        super(TestFunctional, self).setUp()

        # Load config from json test config
        jsonloader.conf.load_str_data(json.dumps(self.sample_conf))
        jsonloader.conf.load_extensions()
        self.conf = jsonloader.conf._config
        ca_conf = self.conf["signing_ca"]["default_ca"]
        ca_conf["output_path"] = tempfile.mkdtemp()

        # Set CA file permissions
        os.chmod(ca_conf["cert_path"], stat.S_IRUSR | stat.S_IFREG)
        os.chmod(ca_conf["key_path"], stat.S_IRUSR | stat.S_IFREG)

        app_conf = {"app": copy.deepcopy(config.app),
                    "logging": copy.deepcopy(config.logging)}
        self.app = pecan_testing.load_test_app(app_conf)

    def tearDown(self):
        pecan.set_config({}, overwrite=True)
        self.app.reset()

    def test_check_unauthorised(self):
        resp = self.app.post('/v1/sign/default_ra', expect_errors=True)
        self.assertEqual(401, resp.status_int)

    def test_robots(self):
        resp = self.app.get('/robots.txt')
        self.assertEqual(200, resp.status_int)
        self.assertEqual("User-agent: *\nDisallow: /\n", resp.text)

    def test_check_missing_csr(self):
        data = {'user': 'myusername',
                'secret': 'simplepassword',
                'encoding': 'pem'}

        resp = self.app.post('/v1/sign/default_ra', data, expect_errors=True)
        self.assertEqual(400, resp.status_int)

    def test_check_unknown_instance(self):
        data = {'user': 'myusername',
                'secret': 'simplepassword',
                'encoding': 'pem',
                'csr': self.csr_sample}

        resp = self.app.post('/v1/sign/unknown', data, expect_errors=True)
        self.assertEqual(404, resp.status_int)

    def test_check_bad_csr(self):
        data = {'user': 'myusername',
                'secret': 'simplepassword',
                'encoding': 'unknown',
                'csr': self.csr_sample}

        resp = self.app.post('/v1/sign/default_ra', data, expect_errors=True)
        self.assertEqual(400, resp.status_int)

    def test_check_good_csr(self):
        data = {'user': 'myusername',
                'secret': 'simplepassword',
                'encoding': 'pem',
                'csr': self.csr_sample}

        resp = self.app.post('/v1/sign/default_ra', data, expect_errors=False)
        self.assertEqual(200, resp.status_int)

        cert = X509_cert.X509Certificate.from_buffer(resp.text)

        # make sure the cert is what we asked for
        self.assertEqual(("/C=UK/ST=Narnia/L=Funkytown/O=Anchor Testing"
                          "/OU=testing/CN=server1.example.com"
                          "/emailAddress=test@example.com"),
                         str(cert.get_subject()))

        # make sure the cert was issued by anchor
        self.assertEqual("/C=AU/ST=Some-State/O=Herp Derp plc/OU"
                         "=herp.derp.plc/CN=herp.derp.plc",
                         str(cert.get_issuer()))

    def test_check_broken_validator(self):
        data = {'user': 'myusername',
                'secret': 'simplepassword',
                'encoding': 'pem',
                'csr': self.csr_sample}

        derp = mock.MagicMock()
        derp.side_effect = Exception("BOOM")

        derp_ext = stevedore.extension.Extension("broken_validator", None,
                                                 derp, None)
        manager = jsonloader.conf._validators.make_test_instance([derp_ext])
        jsonloader.conf._validators = manager

        ra = jsonloader.conf.registration_authority['default_ra']
        ra['validators'] = {"broken_validator": {}}

        resp = self.app.post('/v1/sign/default_ra', data, expect_errors=True)
        self.assertEqual(500, resp.status_int)
        self.assertTrue(("Internal Validation Error") in str(resp))
        self.assertTrue(derp.called)

    def test_get_ca(self):
        data = {'encoding': 'pem'}

        resp = self.app.get('/v1/ca/default_ra', data, expect_errors=False)
        self.assertEqual(200, resp.status_int)

        cert = X509_cert.X509Certificate.from_buffer(resp.text)

        # make sure the cert is what we asked for
        self.assertEqual("/C=AU/ST=Some-State/O=Herp Derp plc/OU"
                         "=herp.derp.plc/CN=herp.derp.plc",
                         str(cert.get_subject()))
