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

import textwrap
import unittest

from pyasn1.type import univ as asn1_univ

from anchor import certificate_ops
from anchor.X509 import certificate
from anchor.X509 import extension
from anchor.X509 import signing_request
import tests


class UnknownExtension(extension.X509Extension):
    _oid = asn1_univ.ObjectIdentifier("1.2.3.4")
    spec = asn1_univ.Null


class SigningBackendExtensions(tests.DefaultConfigMixin, unittest.TestCase):
    csr_data = textwrap.dedent(u"""
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
        -----END CERTIFICATE REQUEST-----
        """)

    def test_copy_good_extensions(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_data)
        ext = extension.X509ExtensionSubjectAltName()
        ext.add_dns_id("example.com")
        csr.add_extension(ext)

        pem = certificate_ops.sign(csr, self.sample_conf_ca['default_ca'])
        cert = certificate.X509Certificate.from_buffer(pem)
        self.assertEqual(1, len(cert.get_extensions(
            extension.X509ExtensionSubjectAltName)))

    def test_ignore_unknown_extensions(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_data)
        ext = UnknownExtension()
        csr.add_extension(ext)

        pem = certificate_ops.sign(csr, self.sample_conf_ca['default_ca'])
        cert = certificate.X509Certificate.from_buffer(pem)
        self.assertEqual(0, len(cert.get_extensions()))

    def test_fail_critical_unknown_extensions(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_data)
        ext = UnknownExtension()
        ext.set_critical(True)
        csr.add_extension(ext)

        with self.assertRaises(certificate_ops.SigningError):
            certificate_ops.sign(csr, self.sample_conf_ca['default_ca'])
