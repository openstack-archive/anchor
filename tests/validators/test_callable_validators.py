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

import textwrap
import unittest

import mock

from anchor import validators
from anchor.X509 import name
from anchor.X509 import signing_request


class TestValidators(unittest.TestCase):
    csr_data_good_subjectAltNames = textwrap.dedent("""
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
    """
    Subject: C=GB, ST=California, L=San Francsico,
                O=OSSG, OU=OSSG, CN=master.test.com
    X509v3 Subject Alternative Name:
                DNS:server1.test.com, DNS:server2.test.com
    """

    csr_data_bad_subjectAltNames = textwrap.dedent("""
        -----BEGIN CERTIFICATE REQUEST-----
        MIID9zCCAl8CAQAwXTELMAkGA1UEBhMCR0IxEzARBgNVBAgTCkNhbGlmb3JuaWEx
        ITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEWMBQGA1UEAxMNb3Nz
        Zy50ZXN0LmNvbTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALnhCRvw
        MoaZa4car663lwcwn86PO3BS90X8b2wIZjkfrq/eePz2J3Ox8/BbsYiYICHn8oSd
        /VVXUnqHMFU9xTeJwsDLbyc+0P4S9Fj+RkbMW+YQZsG8Wy9M8aKi9hNtIGiqknyz
        cOfCQcGPpcKqXRXAW1afqLmifBcFqN1qcpT8OooGNtgo4Ix/fA7omZaKkIXSi5Fo
        vC8mFPUm2VqDyvctxBGq0EngIOB9rczloun0nO8PpWBsX2rg3uIs6GIejVrx1Zkc
        HxJbrze/Nt9vt4C11hJAiAUlHDl0cf50/Pckg0T3ehEqr0zdzCx+wXr3AzStcoOo
        w+REb8CbTt2QaUbZ5izrZFX0JC73mRtqDhucUxUaguLK9ufhUfA0I1j++w/pQkBE
        u5PGNX7YpRLImEp636lD8RJ9Ced7oii+gjY0OXlVPRv9MMPvkCWnjNjLapz8kzyp
        Jr94BQz1AffHxVfmGGQh60vq4KINm+etuI0QkfI9NRa/ficRhsuh7yxQRwIDAQAB
        oFUwUwYJKoZIhvcNAQkOMUYwRDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAqBgNV
        HREEIzAhghBzZXJ2ZXIxLnRlc3QuY29tgg1iYWRkb21haW4uY29tMA0GCSqGSIb3
        DQEBCwUAA4IBgQCIrwFbBoH35np+aKlxqQmNdy+QwK+S1cJvASzKSRmj+/7cCMsg
        YRofCBtNykkfXIsPQUiU2IACtMu8glrWtAham888XcWx1qBH9W4NEAWiQflvvxEI
        cGaTJhsLSmEhs74dnjQK+qvY6vIdp0+40VFUbTks5kb+EFnoqta0Ih92r9zX/S6X
        9JIFA2I5fBwoMZ0CouXuwdOz5rN1OUaHhVb13J6iWY6luJElQjTodyCsfyBP2F8q
        ofPcJwH10Y2njV1L3n3R3DyCAJpRl4DVUJ5C8nyKAbrIDmwU1bTiY4xl4/HuKHWx
        3bJjouPkjVyipwhT5D+gWh9bYrZH0wHmdh/gHufyHAXngsYvK45Z+8nC9+ci7QAv
        mU1RmrrwfirhG8RU40XwLs5Z+FTD54Hp5bqxpLXiyQfutnSGyQUQe9jRoa499xVE
        zsp579hz6O9CjqfkRdjY187Rzwj5vGVf2ZN/pCMiyQd8HwQ/81QNe6hkZrOKbnuK
        GEHeTtZwEvzgF9s=
        -----END CERTIFICATE REQUEST-----""")
    """
    Subject: C=GB, ST=California, CN=ossg.test.com
    X509v3 Subject Alternative Name:
                DNS:server1.test.com, DNS:baddomain.com
    """

    csr_data_good_subjectAltNames_IP = textwrap.dedent("""
        -----BEGIN CERTIFICATE REQUEST-----
        MIID/zCCAmcCAQAwXzELMAkGA1UEBhMCR0IxEzARBgNVBAgTCkNhbGlmb3JuaWEx
        ITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEYMBYGA1UEAxMPbWFz
        dGVyLnRlc3QuY29tMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAueEJ
        G/AyhplrhxqvrreXBzCfzo87cFL3RfxvbAhmOR+ur954/PYnc7Hz8FuxiJggIefy
        hJ39VVdSeocwVT3FN4nCwMtvJz7Q/hL0WP5GRsxb5hBmwbxbL0zxoqL2E20gaKqS
        fLNw58JBwY+lwqpdFcBbVp+ouaJ8FwWo3WpylPw6igY22CjgjH98DuiZloqQhdKL
        kWi8LyYU9SbZWoPK9y3EEarQSeAg4H2tzOWi6fSc7w+lYGxfauDe4izoYh6NWvHV
        mRwfEluvN78232+3gLXWEkCIBSUcOXRx/nT89ySDRPd6ESqvTN3MLH7BevcDNK1y
        g6jD5ERvwJtO3ZBpRtnmLOtkVfQkLveZG2oOG5xTFRqC4sr25+FR8DQjWP77D+lC
        QES7k8Y1ftilEsiYSnrfqUPxEn0J53uiKL6CNjQ5eVU9G/0ww++QJaeM2MtqnPyT
        PKkmv3gFDPUB98fFV+YYZCHrS+rgog2b5624jRCR8j01Fr9+JxGGy6HvLFBHAgMB
        AAGgWzBZBgkqhkiG9w0BCQ4xTDBKMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMDAG
        A1UdEQQpMCeCEHNlcnZlcjEudGVzdC5jb22CDWJhZGRvbWFpbi5jb22HBAoBAQEw
        DQYJKoZIhvcNAQELBQADggGBAGLyVNz4W91YR68MSD1RLnaKuJJJLAMeRmx+F33A
        gQ1gKK6w6que/Qd1jANvsZtSJ3Yei6elbDsepgso63lb6XjdxVDEKv565/PeixF2
        zCDkqtWAlVmcP7RV+zi+6yCNWOToLkbhxnMNYSnvFgXMZ8zoAyGyOVBOiejXxaLh
        84jMnVghGjaRrvUGt36NFptrTC7gHDkBIDoPrRzl3xNREGWijem+Z8PqdORp3LYl
        KaekBJmrun4VMXyW+2+M70mWB/nBsT4SEnFOvWaIEnPrZ5E0GhLcQretmxwrTnV1
        FyYBoTpJUjgTruIj3TULrV/GGIfT5TPZtbEEcb4neX1XPzRAbkYcIrO44PUo8wZn
        w4KlyZ1wtNxwCp6nKWw857P/gGMQ2hdvR57uw4EWv7ogbjZ24kKYqKiTrtoDyMXh
        J3m40t2hSw0L5HNFXI5FlWMiF3oWAyhKA8GTQ9d95FM015KYsY0XeVbIT73Du+ai
        yH77Of+HVIFAaZAG6NnPu8t1eg==
        -----END CERTIFICATE REQUEST-----""")
    """
    Subject: C=GB, ST=California, CN=master.test.com
    X509v3 Subject Alternative Name:
        DNS:server1.test.com, DNS:baddomain.com, IP Address:10.1.1.1
    """

    def setUp(self):
        super(TestValidators, self).setUp()

        self.csr_good_sub_alt_names = signing_request.X509Csr()
        self.csr_good_sub_alt_names.from_buffer(
            TestValidators.csr_data_good_subjectAltNames)

        self.csr_bad_sub_alt_names = signing_request.X509Csr()
        self.csr_bad_sub_alt_names.from_buffer(
            TestValidators.csr_data_bad_subjectAltNames)

        self.csr_good_sub_alt_names_IP = signing_request.X509Csr()
        self.csr_good_sub_alt_names_IP.from_buffer(
            TestValidators.csr_data_good_subjectAltNames_IP)

    def tearDown(self):
        super(TestValidators, self).tearDown()

    @mock.patch('socket.gethostbyname_ex')
    def test_check_networks_both(self, gethostbyname_ex):
        allowed_networks = ['15/8', '74.125/16']
        gethostbyname_ex.return_value = (
            'example.com',
            [],
            [
                '74.125.224.64',
                '74.125.224.67',
                '74.125.224.68',
                '74.125.224.70',
            ]
        )
        self.assertTrue(validators.check_networks(
            'example.com', allowed_networks))
        self.assertTrue(validators.check_networks_strict(
            'example.com', allowed_networks))

        gethostbyname_ex.return_value = ('example.com', [], ['12.2.2.2'])
        self.assertFalse(validators.check_networks(
            'example.com', allowed_networks))

        gethostbyname_ex.return_value = (
            'example.com',
            ['mock.mock'],
            [
                '15.8.2.2',
                '15.8.2.1',
                '16.1.1.1',
            ]
        )
        self.assertFalse(validators.check_networks_strict(
            'example.com', allowed_networks))

    @mock.patch('anchor.X509.name.X509Name.get_entries_by_nid_name')
    def test_common_name_with_two_CN(self, get_entries_by_nid_name):
        get_entries_by_nid_name.return_value = ['1', '2']
        self.assertRaises(
            validators.ValidationError,
            validators.common_name,
            self.csr_good_sub_alt_names,
            allowed_domains=[],
            allowed_networks=[]
        )

    @mock.patch('anchor.X509.signing_request.X509Csr.get_subject')
    @mock.patch('anchor.X509.name.X509Name.get_entries_by_nid_name')
    @mock.patch('anchor.X509.signing_request.X509Csr.get_extensions')
    def test_common_name_no_CN(self, get_extensions, get_entries_by_nid_name,
                               get_subject):
        get_extensions.return_value = []
        get_entries_by_nid_name.return_value = None
        get_subject.return_value = name.X509Name()
        self.assertRaises(
            validators.ValidationError,
            validators.common_name,
            self.csr_good_sub_alt_names,
            allowed_domains=[],
            allowed_networks=[]
        )

    @mock.patch('socket.gethostbyname_ex')
    def test_common_name_good_CN(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('master.test.com', [], ['10.0.0.1'])
        self.assertEqual(
            None,
            validators.common_name(
                self.csr_good_sub_alt_names,
                allowed_domains=['.test.com'],
                allowed_networks=['10/8']
            )
        )

    @mock.patch('socket.gethostbyname_ex')
    def test_common_name_bad_CN(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('master.test.com', [], ['10.0.0.1'])
        self.assertRaises(
            validators.ValidationError,
            validators.common_name,
            self.csr_good_sub_alt_names,
            allowed_domains=['.fail.com'],
            allowed_networks=['10/8']
        )

    @mock.patch('socket.gethostbyname_ex')
    def test_alternative_names_all_good(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('master.test.com', [], ['10.0.0.1'])
        self.assertEqual(
            None,
            validators.alternative_names(
                self.csr_good_sub_alt_names,
                allowed_domains=['.test.com'],
            )
        )

    @mock.patch('socket.gethostbyname_ex')
    def test_alternative_names_bad_domains(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('master.test.com', [], ['10.0.0.1'])
        self.assertRaises(
            validators.ValidationError,
            validators.alternative_names,
            self.csr_bad_sub_alt_names,
            allowed_domains=['.test.com'],  # CSR has a subjalt 'baddomain.com'
        )

    @mock.patch('socket.gethostbyname_ex')
    def test_alternative_names_ip_all_good(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('master.test.com', [], ['10.0.0.1'])
        self.assertEqual(
            None,
            validators.alternative_names_ip(
                self.csr_good_sub_alt_names_IP,
                allowed_domains=['.test.com'],
                allowed_networks=['10/8']
            )
        )

    @mock.patch('socket.gethostbyname_ex')
    def test_alternative_names_ip_bad_network(self, gethostbyname_ex):
        gethostbyname_ex.return_value = ('master.test.com', [], ['10.0.0.1'])
        self.assertRaises(
            validators.ValidationError,
            validators.alternative_names_ip,
            self.csr_good_sub_alt_names_IP,
            allowed_domains=['.test.com'],
            allowed_networks=['99/8']
        )

    @mock.patch('anchor.X509.name.X509Name.Entry.get_name')
    def test_alternative_names_ip_bad_ext(self, get_name):
        get_name.return_value = ('BAD:VALUE')
        self.assertRaises(
            validators.ValidationError,
            validators.alternative_names_ip,
            self.csr_good_sub_alt_names_IP,
            allowed_domains=['mock'],
            allowed_networks=['99/8']
        )
