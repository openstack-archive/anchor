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


import logging

# NOTE(tkelsey): by default Python 2.7 has no default logging handler
# this fixes the "No handler for logger ..." message spam
#
handler = logging.NullHandler()
logging.getLogger().addHandler(handler)


class DefaultConfigMixin(object):
    """Mixin for reuse in any test class which needs to load a config.

    `sample_conf` is always a valid, no thrills configuration. It can be
    reused in any test case. Constructing it in setUp() guarantees that it
    can be changed without affecting other tests.
    """

    def setUp(self):
        self.sample_conf_auth = {
            "default_auth": {
                "backend": "static",
                "user": "myusername",
                "secret": "simplepassword"
            }
        }
        self.sample_conf_ca = {
            "default_ca": {
                "backend": "anchor",
                "cert_path": "tests/CA/root-ca.crt",
                "key_path": "tests/CA/root-ca-unwrapped.key",
                "output_path": "certs",
                "signing_hash": "sha256",
                "valid_hours": 24
            }
        }
        self.sample_conf_validators = {
            "common_name": {
                "allowed_domains": [".test.com"]
            }
        }
        self.sample_conf_ra = {
            "default_ra": {
                "authentication": "default_auth",
                "signing_ca": "default_ca",
                "validators": self.sample_conf_validators
            }
        }
        self.sample_conf = {
            "authentication": self.sample_conf_auth,
            "signing_ca": self.sample_conf_ca,
            "registration_authority": self.sample_conf_ra,
        }

        super(DefaultConfigMixin, self).setUp()
