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

from anchor import certificate_ops
from anchor import jsonloader
from anchor.X509 import name as x509_name
import tests


class CertificateOpsTests(tests.DefaultConfigMixin, tests.DefaultRequestMixin,
                          unittest.TestCase):

    def setUp(self):
        jsonloader.conf.load_extensions()
        super(CertificateOpsTests, self).setUp()

    def tearDown(self):
        pass

    def test_parse_csr_success1(self):
        """Test basic success path for parse_csr."""
        result = certificate_ops.parse_csr(self.csr_sample, 'pem')
        subject = result.get_subject()
        actual_cn = subject.get_entries_by_oid(
            x509_name.OID_commonName)[0].get_value()
        self.assertEqual(actual_cn, self.csr_sample_cn)

    def test_parse_csr_success2(self):
        """Test basic success path for parse_csr."""
        result = certificate_ops.parse_csr(self.csr_sample, 'PEM')
        subject = result.get_subject()
        actual_cn = subject.get_entries_by_oid(
            x509_name.OID_commonName)[0].get_value()
        self.assertEqual(actual_cn, self.csr_sample_cn)

    def test_parse_csr_fail1(self):
        """Test invalid CSR format (wrong value) for parse_csr."""
        with self.assertRaises(http_status.HTTPClientError):
            certificate_ops.parse_csr(self.csr_sample, 'blah')

    def test_parse_csr_fail2(self):
        """Test invalid CSR format (wrong type) for parse_csr."""
        with self.assertRaises(http_status.HTTPClientError):
            certificate_ops.parse_csr(self.csr_sample, True)

    def test_parse_csr_fail3(self):
        """Test invalid CSR (None) format for parse_csr."""
        with self.assertRaises(http_status.HTTPClientError):
            certificate_ops.parse_csr(None, 'pem')

    def test_parse_csr_fail4(self):
        """Test invalid CSR (wrong value) format for parse_csr."""
        with self.assertRaises(http_status.HTTPClientError):
            certificate_ops.parse_csr('invalid csr input', 'pem')

    def test_validate_csr_success(self):
        """Test basic success path for validate_csr."""
        csr_obj = certificate_ops.parse_csr(self.csr_sample, 'pem')
        config = "anchor.jsonloader.conf._config"
        self.sample_conf_ra['default_ra']['validators'] = {'extensions': {
            'allowed_extensions': ['basicConstraints', 'keyUsage']}}
        data = self.sample_conf

        with mock.patch.dict(config, data):
            certificate_ops.validate_csr('default_ra', None, csr_obj, None)

    def test_validate_csr_bypass(self):
        """Test empty validator set for validate_csr."""
        csr_obj = certificate_ops.parse_csr(self.csr_sample, 'pem')
        config = "anchor.jsonloader.conf._config"
        self.sample_conf_ra['default_ra']['validators'] = {}
        data = self.sample_conf

        with mock.patch.dict(config, data):
            # this should work, it allows people to bypass validation
            certificate_ops.validate_csr('default_ra', None, csr_obj, None)

    def test_validate_csr_fail(self):
        """Test failure path for validate_csr."""
        csr_obj = certificate_ops.parse_csr(self.csr_sample, 'pem')
        config = "anchor.jsonloader.conf._config"
        self.sample_conf_ra['default_ra']['validators'] = {
            'common_name': {
                'allowed_domains': ['.testing.example.com']
            }
        }
        data = self.sample_conf

        with mock.patch.dict(config, data):
            with self.assertRaises(http_status.HTTPException) as cm:
                certificate_ops.validate_csr('default_ra', None, csr_obj, None)
        self.assertEqual(cm.exception.code, 400)

    def test_ca_cert_read_failure(self):
        """Test CA certificate read failure."""
        csr_obj = certificate_ops.parse_csr(self.csr_sample, 'pem')
        config = "anchor.jsonloader.conf._config"
        ca_conf = self.sample_conf_ca['default_ca']
        ca_conf['cert_path'] = '/xxx/not/a/valid/path'
        ca_conf['key_path'] = 'tests/CA/root-ca-unwrapped.key'
        data = self.sample_conf

        with mock.patch.dict(config, data):
            with self.assertRaises(http_status.HTTPException) as cm:
                certificate_ops.dispatch_sign('default_ra', csr_obj)
        self.assertEqual(cm.exception.code, 500)

    def test_ca_key_read_failure(self):
        """Test CA key read failure."""
        csr_obj = certificate_ops.parse_csr(self.csr_sample, 'pem')
        config = "anchor.jsonloader.conf._config"
        self.sample_conf_ca['default_ca']['cert_path'] = 'tests/CA/root-ca.crt'
        self.sample_conf_ca['default_ca']['key_path'] = '/xxx/not/a/valid/path'
        data = self.sample_conf

        with mock.patch.dict(config, data):
            with self.assertRaises(http_status.HTTPException) as cm:
                certificate_ops.dispatch_sign('default_ra', csr_obj)
        self.assertEqual(cm.exception.code, 500)

    def test_ca_cert_not_configured(self):
        """Test CA cert read failure."""
        config = "anchor.jsonloader.conf._config"
        self.sample_conf_ca['default_ca']['cert_path'] = None
        data = self.sample_conf

        with mock.patch.dict(config, data):
            with self.assertRaises(http_status.HTTPException) as cm:
                certificate_ops.get_ca('default_ra')
        self.assertEqual(cm.exception.code, 404)
