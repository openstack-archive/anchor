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

from anchor import jsonloader

import logging
import sys
import unittest

import mock


logger = logging.getLogger(__name__)

# find the class representing an open file; it depends on the python version
# it's used later for mocking
if sys.version_info[0] < 3:
    file_class = file
else:
    import _io
    file_class = _io.TextIOWrapper


class TestConfig(unittest.TestCase):
    sample_config = """
    {
      "auth": {
        "static": {
          "secret": "simplepassword",
          "user": "myusername"
        }
      },
      "ca": {
        "cert_path": "tests/CA/root-ca.crt",
        "key_path": "tests/CA/root-ca-unwrapped.key",
        "output_path": "certs",
        "signing_hash": "sha1",
        "valid_hours": 24
      },
      "instances": {
        "default": {
          "validators": {
            "common_name": {
              "allowed_domains": [
                ".test.com"
                  ]
            }
          }
        }
      }
    }
    """

    def test_wrong_key(self):
        """Wrong config key should raise the right error."""
        jsonloader.conf = jsonloader.AnchorConf(logger)

        with self.assertRaises(AttributeError):
            jsonloader.conf.abcdef

    def test_load_file(self):
        """Test loading of a correct configuration."""
        jsonloader.conf = jsonloader.AnchorConf(logger)

        open_name = 'anchor.jsonloader.open'
        with mock.patch(open_name, create=True) as mock_open:
            mock_open.return_value = mock.MagicMock(spec=file_class)
            m_file = mock_open.return_value.__enter__.return_value
            m_file.read.return_value = self.sample_config

            jsonloader.conf.load_file_data('/tmp/impossible_path')

        self.assertEqual(
            jsonloader.conf.instances['default']['auth']['static']['user'],
            'myusername')
        self.assertEqual(
            jsonloader.conf.instances['default']['ca']['valid_hours'],
            24)

    def test_load_file_cant_open(self):
        """Test failures when opening files."""
        jsonloader.conf = jsonloader.AnchorConf(logger)

        open_name = 'anchor.jsonloader.open'
        with mock.patch(open_name, create=True) as mock_open:
            mock_open.return_value = mock.MagicMock(spec=file_class)
            mock_open.side_effect = IOError("can't open file")

            with self.assertRaises(IOError):
                jsonloader.conf.load_file_data('/tmp/impossible_path')

    def test_load_file_cant_parse(self):
        """Test failues when parsing json format."""
        jsonloader.conf = jsonloader.AnchorConf(logger)

        open_name = 'anchor.jsonloader.open'
        with mock.patch(open_name, create=True) as mock_open:
            mock_open.return_value = mock.MagicMock(spec=file_class)
            m_file = mock_open.return_value.__enter__.return_value
            m_file.read.return_value = "{{{{ bad json"

            with self.assertRaises(ValueError):
                jsonloader.conf.load_file_data('/tmp/impossible_path')

    def test_instance_names(self):
        """Instances should be listed once config is loaded."""
        jsonloader.conf = jsonloader.AnchorConf(logger)
        jsonloader.conf.load_str_data(self.sample_config)
        self.assertEqual(list(jsonloader.instance_names()), ['default'])
