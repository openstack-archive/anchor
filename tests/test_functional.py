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
import tempfile
import textwrap
import unittest

import pecan
from pecan import testing as pecan_testing

from anchor import jsonloader
from anchor.X509 import certificate as X509_cert
import config


class TestFunctional(unittest.TestCase):
    config = """
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
      "validators": [
        {
          "name": "default",
          "steps": [
            [
              "common_name",
              {
                "allowed_domains": [
                  ".test.com"
                ]
              }
            ]
          ]
        }
      ]
    }
    """

    csr_good = textwrap.dedent("""
        -----BEGIN CERTIFICATE REQUEST-----
        MIIEDzCCAncCAQAwcjELMAkGA1UEBhMCR0IxEzARBgNVBAgTCkNhbGlmb3JuaWEx
        FjAUBgNVBAcTDVNhbiBGcmFuY3NpY28xDTALBgNVBAoTBE9TU0cxDTALBgNVBAsT
        BE9TU0cxGDAWBgNVBAMTD21hc3Rlci50ZXN0LmNvbTCCAaIwDQYJKoZIhvcNAQEB
        BQADggGPADCCAYoCggGBALnhCRvwMoaZa4car663lwcwn86PO3BS90X8b2wIZjkf
        rq/eePz2J3Ox8/BbsYiYICHn8oSd/VVXUnqHMFU9xTeJwsDLbyc+0P4S9Fj+RkbM
        W+YQZsG8Wy9M8aKi9hNtIGiqknyzcOfCQcGPpcKqXRXAW1afqLmifBcFqN1qcpT8
        OooGNtgo4Ix/fA7omZaKkIXSi5FovC8mFPUm2VqDyvctxBGq0EngIOB9rczloun0
        nO8PpWBsX2rg3uIs6GIejVrx1ZkcHxJbrze/Nt9vt4C11hJAiAUlHDl0cf50/Pck
        g0T3ehEqr0zdzCx+wXr3AzStcoOow+REb8CbTt2QaUbZ5izrZFX0JC73mRtqDhuc
        UxUaguLK9ufhUfA0I1j++w/pQkBEu5PGNX7YpRLImEp636lD8RJ9Ced7oii+gjY0
        OXlVPRv9MMPvkCWnjNjLapz8kzypJr94BQz1AffHxVfmGGQh60vq4KINm+etuI0Q
        kfI9NRa/ficRhsuh7yxQRwIDAQABoFgwVgYJKoZIhvcNAQkOMUkwRzAJBgNVHRME
        AjAAMAsGA1UdDwQEAwIF4DAtBgNVHREEJjAkghBzZXJ2ZXIxLnRlc3QuY29tghBz
        ZXJ2ZXIyLnRlc3QuY29tMA0GCSqGSIb3DQEBCwUAA4IBgQBdyATuNnfVIeQL2odc
        zV7f9c/tvN5/Mn4AmGt5S457FGO/s3J7hWX9L02VYPWwORbtkBvZZKtQWLjHbMzU
        oGsfxeo6vUv+dSP6bjqKibFyMArdaRIobFMvM/5N6g9zcP4sQEnpUyIeV2g6b0Os
        FoKGsLPIMiS69mAVdfKrgXnmXApXu5zjAoPnSzcc+wKTCbzVIRLZIopEtet84atN
        7Tf9xokgrDZppJE76w3zXYWPkUDbVuWTuO4afQxujHbJYiZblxJz/gRbMgugAt4V
        ftlI3EGnGaBQHcZfmyZz1F8ti1jteWMMQZHtWr32cF9Lw/jd2adYFYVTez3BXtQW
        pULCxdq8G2CFdrV/atIL8Vadf2dOzn2tZIFFihzuilWbcmTP7+8UI8MOKkrqfWN+
        Q6yV3I896rSprU7WAmWSq+jXkOOwNGDEbmaWsxu4AjvfGty5v2lZqdYJRkbjerXD
        tR7XqQGqJKca/vRTfJ+zIAxMEeH1N9Lx7YBO6VdVja+yG1E=
        -----END CERTIFICATE REQUEST-----""")

    csr_bad = textwrap.dedent("""
        -----BEGIN CERTIFICATE REQUEST-----
        MIIBWTCCARMCAQAwgZQxCzAJBgNVBAYTAlVLMQ8wDQYDVQQIEwZOYXJuaWExEjAQ
        BgNVBAcTCUZ1bmt5dG93bjEXMBUGA1UEChMOQW5jaG9yIFRlc3RpbmcxEDAOBgNV
        BAsTB3Rlc3RpbmcxFDASBgNVBAMTC2FuY2hvci50ZXN0MR8wHQYJKoZIhvcNAQkB
        FhB0ZXN0QGFuY2hvci50ZXN0MEwwDQYJKoZIhvcNAQEBBQADOwAwOAIxAOpvxkCx
        NNTc86GVnP4rWvaniOnHaemXbhBOoFxhMwaghiq7u5V9ZKkUZfbu+L+ZSQIDAQAB
        oCkwJwYJKoZIhvcNAQkOMRowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DANBgkq
        hkiG9w0BAQUFAAMxALaK8/HR73ZSvHiWo7Mduin0S519aJBm+gO8d9iliUkK00gQ
        VMs9DuTAxljX7t7Eug==
        -----END CERTIFICATE REQUEST-----""")

    def setUp(self):
        app_conf = {"app": copy.deepcopy(config.app),
                    "logging": copy.deepcopy(config.logging)}
        self.app = pecan_testing.load_test_app(app_conf)
        jsonloader.conf.load_str_data(TestFunctional.config)

        self.conf = getattr(jsonloader.conf, "_config")
        self.conf["ca"]["output_path"] = tempfile.mkdtemp()

    def tearDown(self):
        pecan.set_config({}, overwrite=True)
        self.app.reset()

    def test_check_unauthorised(self):
        resp = self.app.post('/sign', expect_errors=True)
        self.assertEqual(401, resp.status_int)

    def test_check_missing_csr(self):
        data = {'user': 'myusername',
                'secret': 'simplepassword',
                'encoding': 'pem'}

        resp = self.app.post('/sign', data, expect_errors=True)
        self.assertEqual(400, resp.status_int)

    def test_check_bad_csr(self):
        data = {'user': 'myusername',
                'secret': 'simplepassword',
                'encoding': 'pem',
                'csr': TestFunctional.csr_bad}

        resp = self.app.post('/sign', data, expect_errors=True)
        self.assertEqual(400, resp.status_int)

    def test_check_good_csr(self):
        data = {'user': 'myusername',
                'secret': 'simplepassword',
                'encoding': 'pem',
                'csr': TestFunctional.csr_good}

        resp = self.app.post('/sign', data, expect_errors=False)
        self.assertEqual(200, resp.status_int)

        cert = X509_cert.X509Certificate()
        cert.from_buffer(resp.text)

        # make sure the cert is what we asked for
        self.assertEqual(("/C=GB/ST=California/L=San Francsico/O=OSSG"
                          "/OU=OSSG/CN=master.test.com"),
                         str(cert.get_subject()))

        # make sure the cert was issued by anchor
        self.assertEqual("/C=UK/ST=Some-State/O=OSSG/CN=anchor.example.com",
                         str(cert.get_issuer()))
