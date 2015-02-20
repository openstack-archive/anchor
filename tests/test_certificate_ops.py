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

import textwrap
import unittest

import mock
from webob import exc as http_status

from anchor import certificate_ops


class CertificateOpsTests(unittest.TestCase):

    def setUp(self):
        # This is a CSR with CN=anchor-test.example.com
        self.expected_cn = "anchor-test.example.com"
        self.csr = textwrap.dedent("""
            -----BEGIN CERTIFICATE REQUEST-----
            MIIEsDCCApgCAQAwazELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEx
            FjAUBgNVBAcTDU1vdW50YWluIFZpZXcxDTALBgNVBAoTBEFjbWUxIDAeBgNVBAMT
            F2FuY2hvci10ZXN0LmV4YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
            MIICCgKCAgEAvRri1XL/BIR882HdRisntITkEwDmBUmNcVKioOOc6wfLDzhrDFZc
            fo34CvSPm4q4qlnGd4mmJt6rmDwZFhp4PPWHvZ4XWNygI0hZK3P+R6YZWOe2EwCU
            M2+yCLLDAVucQZmqFtKLv3fedjM3udgEHrf6rf8eyE9X0eyXGJ7jNLEQvJktpr6v
            JrKnMVssyzUXek4ZiWUoMY864MYeG+ZbdeHzSCMC9iCdfQIdTGUJ0SclOPoRPSUu
            zyTE4FfDFLCZof6gcYudpdSK4Iy84G89kIb1Yfdvg5ak71uMtPRxSncsbfg4TK8r
            WuyXs4alIA5bunhf89b6zt3BKufTzs6jBi9oLertafPW9Xgl2PbIeyN9JH1207/L
            EnXpTS5XK/SDRnzkKCe9aSHy+mS77bRQjV+U67V+TVc9OrbZYQ5krHb3mlWf31wU
            owS0d7DQLhGrPtBs/C85u4DUTHJcZys7RX4Q7fArDkN1sszhtoxNb2WTgYLKYQYF
            IHdYRF8Bqq7ZrNJ+2MOQS1kowXTluJKuCQbgL+UwJl+wtrRdxt64CKSCmtH7h4H+
            yhDD2J6CP3jz4SUQY/CxCmHzI1SVDmHwtr7J02V468Bz+zwT9YbLyvwPKAKJAW5h
            MUpYN+Yg6Ch7TEa/qw+tbkJbSQeXiAIpzRVAzffo8+djG+UnMdLSMBcCAwEAAaAA
            MA0GCSqGSIb3DQEBBQUAA4ICAQAr3YwkjT9Lft7DQP328BfudnAQR+tdodAtZGRU
            y3ZUVupQwgtYdCCRnneCdVcAQUnj6tZHkzBhHBflVz24vXZZHiQilaajzeCoJpj5
            jXy1ZjPK/efTKw8H325N8hHqGgiXEp86K06LZ4a6m3K+lBZbhb2hSt2MJx8DDn1Y
            YE1Ssvo0rxDrhnPbAeAdmVNT4zCazYTAaYk2IwAAY9BsoRQouYsSHbVxG+KFGp2A
            Rw9ryCqBXUAbj0b7whOFEj7pqg3F8nNbPuFdaUoCGaN8TWQFy4diwFsujGONDl4w
            Df82BlAj/ty9z5WUCs01+z9X4SDm+vchSMqBKgAYZSKEAEmlQf++3tlJpEG7jM1l
            SqYkeSVWrkHSBXkNQQ2iNmzMBvCA40Qont8OXP/gqS0+rS37f2LtuUueCgV8Gtay
            RWgH7/JcdLEMm/XohRyD2yVz/JhKNWkYyEjtpr4wFTgFX48v6H4fE7o0HcUHy4nK
            vN4vwXoa71x65lL1HcZdqYr/ff9KHcwxaOnflTgXzBMvm++F7EwEOK61TDuNkZ8h
            gaf8Ejt1XNtA1jPNnRES7gqafOJAwYyshr5XoLzHUgbXBTVlEp5t2buxf76n+nzz
            Zz6BD8nuXQMGPy60ql12MQvLmdX7mFFHthucExhA/9R7wSPtdS8OBPljumgUuhRR
            BcW7kw==
            -----END CERTIFICATE REQUEST-----""")
        super(CertificateOpsTests, self).setUp()

    def tearDown(self):
        pass

    def test_parse_csr_success1(self):
        """Test basic success path for parse_csr."""
        result = certificate_ops.parse_csr(self.csr, 'pem')
        subject = result.get_subject()
        actual_cn = subject.get_entries_by_nid_name('CN')[0].get_value()
        self.assertEqual(actual_cn, self.expected_cn)

    def test_parse_csr_success2(self):
        """Test basic success path for parse_csr."""
        result = certificate_ops.parse_csr(self.csr, 'PEM')
        subject = result.get_subject()
        actual_cn = subject.get_entries_by_nid_name('CN')[0].get_value()
        self.assertEqual(actual_cn, self.expected_cn)

    def test_parse_csr_fail1(self):
        """Test invalid CSR format (wrong value) for parse_csr."""
        with self.assertRaises(http_status.HTTPClientError):
            certificate_ops.parse_csr(self.csr, 'blah')

    def test_parse_csr_fail2(self):
         """Test invalid CSR format (wrong type) for parse_csr."""
        with self.assertRaises(http_status.HTTPClientError):
            certificate_ops.parse_csr(self.csr, True)

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
        csr_obj = certificate_ops.parse_csr(self.csr, 'pem')
        config = "pecan.conf.__values__"
        validators = [{'name': 'common',
                       'steps': [
                           ('extensions', {'allowed_extensions': []})]}]
        data = {'validators': validators}

        with mock.patch.dict(config, data):
            certificate_ops.validate_csr(None, csr_obj, None)

    def test_validate_csr_fail1(self):
        """Test empty validator set for validate_csr."""
        config = "pecan.conf.__values__"
        data = {'validators': []}

        with mock.patch.dict(config, data):
            # this should work, it allows people to bypass validation
            certificate_ops.validate_csr(None, None, None)

    def test_validate_csr_fail2(self):
        """Test invalid validator set (no tuples) for validate_csr."""
        config = "pecan.conf.__values__"
        validators = [{'name': 'common', 'steps': [True]}]
        data = {'validators': validators}

        with mock.patch.dict(config, data):
            with self.assertRaises(http_status.HTTPClientError):
                certificate_ops.validate_csr(None, None, None)

    def test_validate_csr_fail3(self):
        """Test invalid validator set (tuple too long) for validate_csr."""
        config = "pecan.conf.__values__"
        validators = [{'name': 'common', 'steps': [(1, 2, 3)]}]
        data = {'validators': validators}

        with mock.patch.dict(config, data):
            with self.assertRaises(http_status.HTTPClientError):
                certificate_ops.validate_csr(None, None, None)

    def test_validate_csr_fail4(self):
        """Test invalid validator set (bogus validator) for validate_csr."""
        config = "pecan.conf.__values__"
        validators = [{'name': 'common', 'steps': [('no_such_method')]}]
        data = {'validators': validators}

        with mock.patch.dict(config, data):
            with self.assertRaises(http_status.HTTPClientError):
                certificate_ops.validate_csr(None, None, None)

    def test_validate_csr_fail5(self):
        """Test validate_csr with a validator that should fail."""
        csr_obj = certificate_ops.parse_csr(self.csr, 'pem')
        config = "pecan.conf.__values__"
        validators = [{'name': 'common', 'steps': [('common_name')]}]
        data = {'validators': validators}

        with mock.patch.dict(config, data):
            with self.assertRaises(http_status.HTTPClientError):
                certificate_ops.validate_csr(None, csr_obj, None)
