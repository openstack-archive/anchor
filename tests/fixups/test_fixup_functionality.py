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

import mock
import webob

from anchor import certificate_ops
from anchor import jsonloader
from anchor.X509 import signing_request
import tests


class TestFixupFunctionality(tests.DefaultConfigMixin,
                             tests.DefaultRequestMixin,
                             unittest.TestCase):
    def setUp(self):
        super(TestFixupFunctionality, self).setUp()
        jsonloader.conf.load_extensions()
        self.csr = signing_request.X509Csr.from_buffer(
            TestFixupFunctionality.csr_sample_bytes)

    def test_with_noop(self):
        """Ensure single fixup is processed."""

        self.sample_conf_ra['default_ra']['fixups'] = {'noop': {}}
        data = self.sample_conf

        config = "anchor.jsonloader.conf._config"
        mock_noop = mock.MagicMock()
        mock_noop.name = "noop"
        mock_noop.plugin.return_value = self.csr

        jsonloader.conf._fixups = jsonloader.conf._fixups.make_test_instance(
            [mock_noop], 'anchor.fixups')

        with mock.patch.dict(config, data):
            certificate_ops.fixup_csr('default_ra', self.csr, None)

        mock_noop.plugin.assert_called_with(
            csr=self.csr, conf=self.sample_conf_ra['default_ra'], request=None)

    def test_with_no_fixups(self):
        """Ensure no fixups is ok."""

        self.sample_conf_ra['default_ra']['fixups'] = {}
        data = self.sample_conf

        config = "anchor.jsonloader.conf._config"
        with mock.patch.dict(config, data):
            res = certificate_ops.fixup_csr('default_ra', self.csr, None)
        self.assertIs(res, self.csr)

    def test_with_broken_fixup(self):
        """Ensure broken fixups stop processing."""

        self.sample_conf_ra['default_ra']['fixups'] = {'broken': {}}
        data = self.sample_conf

        config = "anchor.jsonloader.conf._config"
        mock_noop = mock.MagicMock()
        mock_noop.name = "broken"
        mock_noop.plugin.side_effects = Exception("BOOM")

        jsonloader.conf._fixups = jsonloader.conf._fixups.make_test_instance(
            [mock_noop], 'anchor.fixups')

        with mock.patch.dict(config, data):
            with self.assertRaises(webob.exc.WSGIHTTPException):
                certificate_ops.fixup_csr('default_ra', self.csr, None)
