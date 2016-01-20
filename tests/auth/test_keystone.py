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
import uuid

import mock
import requests
import requests_mock

from anchor.auth import keystone
from anchor.auth import results


class AuthKeystoneTests(unittest.TestCase):

    def setUp(self):
        self.config = "anchor.jsonloader.conf._config"
        self.data = {'auth': {'keystone': {'url': 'http://localhost:35357'}}}
        self.json_response = {
            "token": {
                "audit_ids": [
                    "TPDsHuK_QCaKwvkVlAer8A"
                ],
                "catalog": [
                    {
                        "endpoints": [
                            {
                                "id": "1390df96096d4bd19add44811db34397",
                                "interface": "public",
                                "region": "RegionOne",
                                "region_id": "RegionOne",
                                "url": "http://10.0.2.15:5000/v2.0"
                            },
                            {
                                "id": "534bcae735614781a03069d637b21570",
                                "interface": "internal",
                                "region": "RegionOne",
                                "region_id": "RegionOne",
                                "url": "http://10.0.2.15:5000/v2.0"
                            },
                            {
                                "id": "cc7e879d691e4e4b9f4afecb1a3ce8f0",
                                "interface": "admin",
                                "region": "RegionOne",
                                "region_id": "RegionOne",
                                "url": "http://10.0.2.15:35357/v2.0"
                            }
                        ],
                        "id": "3010a0c9af684db28659f0e9e08ee863",
                        "name": "keystone",
                        "type": "identity"
                    }
                ],
                "expires_at": "2015-07-27T02:38:09.000000Z",
                "extras": {},
                "issued_at": "2015-07-27T01:38:09.409616",
                "methods": [
                    "password",
                    "token"
                ],
                "project": {
                    "domain": {
                        "id": "default",
                        "name": "Default"
                    },
                    "id": "5b2e7bd5d5954fdaa2d931285df8a132",
                    "name": "demo"
                },
                "roles": [
                    {
                        "id": "35a1d29b54f64c969aa9be288ec9d39a",
                        "name": "anotherrole"
                    },
                    {
                        "id": "9f64371fcbd64c669ab1a24686a1a367",
                        "name": "Member"
                    }
                ],
                "user": {
                    "domain": {
                        "id": "default",
                        "name": "Default"
                    },
                    "id": "b2016b9338214cda926d5631c1fbc40c",
                    "name": "demo"
                }
            }
        }

        self.user = self.json_response['token']['user']['name']
        self.roles = [role['name']
                      for role in self.json_response['token']['roles']]
        self.user_id = self.json_response['token']['user']['id']
        self.project_id = self.json_response['token']['project']['id']
        self.expected = results.AuthDetails(
            username=self.user, groups=self.roles,
            user_id=self.user_id, project_id=self.project_id)

        self.keystone_url = self.data['auth'][
            'keystone']['url'] + '/v3/auth/tokens'
        self.keystone_token = uuid.uuid4().hex

        super(AuthKeystoneTests, self).setUp()

    def tearDown(self):
        pass

    def test_parse_keystone_valid_response(self):
        with mock.patch.dict(self.config, self.data):
            with requests_mock.mock() as m:
                m.get(self.keystone_url, json=self.json_response,
                      status_code=200)
                requests.get(self.keystone_url)
                self.assertEqual(keystone.login(
                    None, self.keystone_token), self.expected)

    def test_parse_keystone_auth_fail(self):
        with mock.patch.dict(self.config, self.data):
            with requests_mock.mock() as m:
                m.get(self.keystone_url, status_code=401)
                self.assertEqual(keystone.login(
                    None, self.keystone_token), None)

    def test_parse_keystone_ok_but_malformed_response(self):
        with mock.patch.dict(self.config, self.data):
            with requests_mock.mock() as m:
                m.get(self.keystone_url, json={}, status_code=200)
                self.assertEqual(keystone.login(
                    None, self.keystone_token), None)
