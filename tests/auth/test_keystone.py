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


class AuthKeystoneTests(unittest.TestCase):

    def setUp(self):
        super(AuthKeystoneTests, self).setUp()

    def tearDown(self):
        pass

    def test_auth_login(self):

        config = "anchor.jsonloader.conf._config"
        data = {'auth': {'keystone': {'url': 'http://localhost:35357'}}}
        with mock.patch.dict(config, data):

            from anchor.auth import keystone
            from anchor.auth import results

            keystone_url = data['auth']['keystone']['url'] + '/v3/auth/tokens'
            keystone_token = uuid.uuid4().hex

            json_response = {
                "token": {
                    "roles": [
                        {
                            "name": "admin"
                        }
                    ],
                    "user": {
                        "name": "priti"
                    },
                }
            }

            user = json_response['token']['user']['name']
            roles = [role['name'] for role in json_response['token']['roles']]
            expected = results.AuthDetails(username=user, groups=roles)

            with requests_mock.mock() as m:
                m.post(keystone_url, json=json_response, status_code=200)
                requests.post(keystone_url)
                # Check that it can parse Keystone response when
                # response has valid json and status code of 200
                self.assertEqual(keystone.login(None, keystone_token),
                                 expected)

                # Check that it fails and returns appropriate auth
                # failure when Keystone authentication fails
                m.post(keystone_url, status_code=201)
                self.assertEqual(keystone.login(None, keystone_token),
                                 None)

                # Check that it fails and returns appropriate auth
                # failure when Keystone response is corrupted
                m.post(keystone_url, json={}, status_code=200)
                self.assertEqual(keystone.login(None, keystone_token),
                                 None)
