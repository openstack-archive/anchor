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
import textwrap

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
                "allowed_domains": [".example.com"]
            }
        }
        self.sample_conf_fixups = {
        }
        self.sample_conf_ra = {
            "default_ra": {
                "authentication": "default_auth",
                "signing_ca": "default_ca",
                "validators": self.sample_conf_validators,
                "fixups": self.sample_conf_fixups,
            }
        }
        self.sample_conf = {
            "authentication": self.sample_conf_auth,
            "signing_ca": self.sample_conf_ca,
            "registration_authority": self.sample_conf_ra,
        }

        super(DefaultConfigMixin, self).setUp()


class DefaultRequestMixin(object):
    # CN=server1.example.com
    # 2048 RSA, basicConstraints, keyUsage exts
    csr_sample_cn = 'server1.example.com'
    csr_sample = textwrap.dedent("""
        -----BEGIN CERTIFICATE REQUEST-----
        MIIDDjCCAfYCAQAwgZwxCzAJBgNVBAYTAlVLMQ8wDQYDVQQIEwZOYXJuaWExEjAQ
        BgNVBAcTCUZ1bmt5dG93bjEXMBUGA1UEChMOQW5jaG9yIFRlc3RpbmcxEDAOBgNV
        BAsTB3Rlc3RpbmcxHDAaBgNVBAMTE3NlcnZlcjEuZXhhbXBsZS5jb20xHzAdBgkq
        hkiG9w0BCQEWEHRlc3RAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
        DwAwggEKAoIBAQDhQloUTMZwBFgbseH5vk4S+mgqwyZDytu9S6x7YPv4aav/FTQd
        W/RJB07YvUIZSJ50YScNSzXrtjqqifjdvnyiVYpS+vP8/yZIclJt8BNLwA3ESvHO
        75leRhSahxMkIMW7WfaV4ys8jkGDx3fISCn/jo5zelaLXaiHAzGRRMKefWmy54lX
        W6jh1caoadRsnFQbAmAljW0JNQ53Sr2KOwVu6I8/IJ9PcT16D0WembvuOsNZZ8V9
        y2FYiJ4FYesN9JGoKvBC8U1pr+FXpNfEdaniNbfRsz5gCsap3mxMMLKlFS7AB2ar
        zw5awegV9M7gMYkg4e6HWl33fS+kt/zSC53rAgMBAAGgLDAqBgkqhkiG9w0BCQ4x
        HTAbMAsGA1UdDwQEAwIF4DAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IB
        AQArTSUNFZHqUnCL+TLVgDSq9oaSutO3vu1g+EKfFxN2rG5HrxbAc2eC8TaMfUVd
        D2JaEkhi9X7wPpVKIVwMo4nYVO8ke1MdXRLecNzLRT4sC40ZuOoDxOFEzm5BibGv
        OLty0xKx3fylL0qa+wMXQNDWVcbq3OcJNo4v41fl4jlab4Fx5mWaCnKja+LnJT45
        4wJQQN+UFPwvEt3Ay2UqvzVVUlJ3tO30f5WZitlpYy9txLaV9v6xdc2N/YMgQ7Tz
        DxpZNBHlkA6LWaRqAtWws3uvom7IjHGgSr7UITrOR5iO5Hrm85X7K0AT6Bu75RZL
        +uYLLfj9Nb/iznREl9E3a/fN
        -----END CERTIFICATE REQUEST-----""")
    csr_sample_bytes = csr_sample.encode('ascii')
