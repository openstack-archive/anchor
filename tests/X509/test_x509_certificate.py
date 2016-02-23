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
from pyasn1.type import univ as asn1_univ

import io
import textwrap

from anchor.X509 import certificate
from anchor.X509 import errors as x509_errors
from anchor.X509 import extension
from anchor.X509 import name as x509_name


class TestX509Cert(unittest.TestCase):
    cert_data = textwrap.dedent(u"""
        -----BEGIN CERTIFICATE-----
        MIICuDCCAiGgAwIBAgIJAIaZlZ0Oms2fMA0GCSqGSIb3DQEBCwUAMGoxCzAJBgNV
        BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMRYwFAYDVQQKDA1IZXJwIERlcnAg
        cGxjMRYwFAYDVQQLDA1oZXJwLmRlcnAucGxjMRYwFAYDVQQDDA1oZXJwLmRlcnAu
        cGxjMB4XDTE1MDkwMTIzNDcwNVoXDTE1MDkwMjIzNDcwNVowgZQxCzAJBgNVBAYT
        AlVLMQ8wDQYDVQQIDAZOYXJuaWExEjAQBgNVBAcMCUZ1bmt5dG93bjEXMBUGA1UE
        CgwOQW5jaG9yIFRlc3RpbmcxEDAOBgNVBAsMB3Rlc3RpbmcxFDASBgNVBAMMC2Fu
        Y2hvci50ZXN0MR8wHQYJKoZIhvcNAQkBFhB0ZXN0QGFuY2hvci50ZXN0MIGfMA0G
        CSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeeqg1Qeccv8hqj1BP9KEJX5QsFCxR62M8
        plPb5t4sLo8UYfZd6kFLcOP8xzwwvx/eFY6Sux52enQ197o8aMwyP77hMhZqtd8N
        CgLJMVlUbRhwLti0SkHFPic0wAg+esfXa6yhd5TxC+bti7MgV/ljA80XQxHH8xOj
        dOoGN0DHfQIDAQABozswOTAfBgNVHSMEGDAWgBTe1pcxYWGrNC/uksuFloCGv41g
        3TAJBgNVHRMEAjAAMAsGA1UdDwQEAwIE8DANBgkqhkiG9w0BAQsFAAOBgQAy+2HQ
        kXyNc5SwjvCXMDWMTKSB5bEWPxuJw3Lf1G4czHAyANzGlm1HJ/h6Z8NSwEy9x0xj
        iFnpbc39fGoeApkEqVhY0WyJ7qbCuJsExE+ra6w+iPIKvjez+Ymp+zCDsiTIJEnf
        2jsyzhghVa/FgDpQYQEJHAuGTEAvkQITp8IUvg==
        -----END CERTIFICATE-----""")

    key_dsa_data = textwrap.dedent("""
        -----BEGIN DSA PARAMETERS-----
        MIICLAKCAQEA59W1OsK9Tv7DRbxzibGVpBAL2Oz8JhbV3ii7WAat+UfTBLAnfdva
        7UE8odu1l8p41N/8H/tDWgPh6tOgdX0YT9HDsILymQxzUEscliFZKmYg7YdSH3Zd
        6DglOT7CqYxX0r9gK/BOh8ESe3gqKncnThHnO8Eu9wP8HNcrN00EOqP+fJpbS0lu
        iifD9JdFY5YpCsLDIvpPbM0NCDuANPo10N3qqC8BuNiu0VfZpRSBcqzU1kwABT5n
        y7+8RMh5Xaa7xnhGctJ9s9n+QfWcF/vbgiDOBttb3d8r8Pqvoou8v7Q38Q6zILhf
        hajevqjGqZwodbvbHGfFbWapgBjpBIr4zwIhAOq6uryEHQglirWCGFJLQlkzxghy
        ctHBRXGuKYb+ltRTAoIBAHRUFxzd1vhjKQ5atIdG0AiXUNm7/uboe21EJDLf4lkE
        7UHDZfwsHXxQHfozzIsp7gHcw7F6AVCgiNRi9vBYOemPswevoWiVKqLTVt1wMogD
        EJI6VAQEbBmSrtvyuClCkEAlIY6daX9EV9KqbnetS4/xv4WFQ9FPE47VyQ50vvxK
        JSyNZnJ1lN6FUD9R5YYfwERgND8EYJBD10UBKIvtORICTJUfaDAweTWhaVcXUID7
        VGNGPauOdVQzWsWTrQn/f/hbXCB/KXgv1l92D6rEoT2j2YrqIv/qD/ZxPwhBfLdr
        W241Cb+LT05LVCokRbWUdjfuO8SdSBAIvT9P6umG/uQ=
        -----END DSA PARAMETERS-----
        -----BEGIN DSA PRIVATE KEY-----
        MIIDVwIBAAKCAQEA59W1OsK9Tv7DRbxzibGVpBAL2Oz8JhbV3ii7WAat+UfTBLAn
        fdva7UE8odu1l8p41N/8H/tDWgPh6tOgdX0YT9HDsILymQxzUEscliFZKmYg7YdS
        H3Zd6DglOT7CqYxX0r9gK/BOh8ESe3gqKncnThHnO8Eu9wP8HNcrN00EOqP+fJpb
        S0luiifD9JdFY5YpCsLDIvpPbM0NCDuANPo10N3qqC8BuNiu0VfZpRSBcqzU1kwA
        BT5ny7+8RMh5Xaa7xnhGctJ9s9n+QfWcF/vbgiDOBttb3d8r8Pqvoou8v7Q38Q6z
        ILhfhajevqjGqZwodbvbHGfFbWapgBjpBIr4zwIhAOq6uryEHQglirWCGFJLQlkz
        xghyctHBRXGuKYb+ltRTAoIBAHRUFxzd1vhjKQ5atIdG0AiXUNm7/uboe21EJDLf
        4lkE7UHDZfwsHXxQHfozzIsp7gHcw7F6AVCgiNRi9vBYOemPswevoWiVKqLTVt1w
        MogDEJI6VAQEbBmSrtvyuClCkEAlIY6daX9EV9KqbnetS4/xv4WFQ9FPE47VyQ50
        vvxKJSyNZnJ1lN6FUD9R5YYfwERgND8EYJBD10UBKIvtORICTJUfaDAweTWhaVcX
        UID7VGNGPauOdVQzWsWTrQn/f/hbXCB/KXgv1l92D6rEoT2j2YrqIv/qD/ZxPwhB
        fLdrW241Cb+LT05LVCokRbWUdjfuO8SdSBAIvT9P6umG/uQCggEBAKrZAppbnKf1
        pzSvE3gTaloitAJG+79BML5h1n67EWuv0i+Fq4eUAVJ23R8GR1HrYw6utZoYbu8u
        k8eHrArMfTfbFaLwK/Nv33Hfm3aTTXnY6auLNkpbiZXuCQjWBFhb6F+B42V9/JJ8
        RJ1UV6Y2ajjjMvpeh0cPlARw5UpKBgQ933DhefCWyFBPsPToFvd3uPO+GUN6VpNY
        iR7G0AH3/LSVJRuz5/QCp86uLIoU3fBEf1KGYJrkVKlc9DtcNmDXgpP0d3fK+4Jw
        bGvi5AD1sQOWryNujyS/d2K/PAagsD0M6XJFgkEV592OSlygbYtuo3t4AtAy8F0f
        VHNXq2l01FMCIQCrkk1749eQg4W6j7HfLFvjbDcuIFTw98IKyEZuZ93cdA==
        -----END DSA PRIVATE KEY-----""").encode('ascii')

    key_rsa_data = textwrap.dedent("""
        -----BEGIN RSA PRIVATE KEY-----
        MIICXAIBAAKBgQCeeqg1Qeccv8hqj1BP9KEJX5QsFCxR62M8plPb5t4sLo8UYfZd
        6kFLcOP8xzwwvx/eFY6Sux52enQ197o8aMwyP77hMhZqtd8NCgLJMVlUbRhwLti0
        SkHFPic0wAg+esfXa6yhd5TxC+bti7MgV/ljA80XQxHH8xOjdOoGN0DHfQIDAQAB
        AoGBAJ2ozJpe+7qgGJPaCz3f0izvBwtq7kR49fqqRZbo8HHnx7OxWVVI7LhOkKEy
        2/Bq0xsvOu1CdiXL4LynvIDIiQqLaeINzG48Rbk+0HadbXblt3nDkIWdYII6zHKI
        W9ewX4KpHEPbrlEO9BjAlAcYsDIvFIMYpQhtQ+0R/gmZ99WJAkEAz5C2a6FIcMbE
        o3aTc9ECq99zY7lxh+6aLpUdIeeHyb/QzfGDBdlbpBAkA6EcxSqp0aqH4xIQnYHa
        3P5ZCShqSwJBAMN1sb76xq94xkg2cxShPFPAE6xKRFyKqLgsBYVtulOdfOtOnjh9
        1SK2XQQfBRIRdG4Q/gDoCP8XQHpJcWMk+FcCQDnuJqulaOVo5GrG5mJ1nCxCAh98
        G06X7lo/7dCPoRtSuMExvaK9RlFk29hTeAcjYCAPWzupyA9dtarmJg1jRT8CQCKf
        gYnb8D/6+9yk0IPR/9ayCooVacCeyz48hgnZowzWs98WwQ4utAd/GED3obVOpDov
        Bl9wus889i3zPoOac+cCQCZHredQcJGd4dlthbVtP2NhuPXz33JuETGR9pXtsDUZ
        uX/nSq1oo9kUh/dPOz6aP5Ues1YVe3LExmExPBQfwIE=
        -----END RSA PRIVATE KEY-----""").encode('ascii')

    def setUp(self):
        super(TestX509Cert, self).setUp()
        self.cert = certificate.X509Certificate.from_buffer(
            TestX509Cert.cert_data)

    def tearDown(self):
        pass

    def test_bad_data_throws(self):
        bad_data = (
            u"some bad data is "
            "EHRlc3RAYW5jaG9yLnRlc3QwTDANBgkqhkiG9w0BAQEFAAM7ADA4AjEA6m")

        cert = certificate.X509Certificate()
        self.assertRaises(x509_errors.X509Error,
                          cert.from_buffer,
                          bad_data)

    def test_get_subject_countryName(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_countryName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "UK")

    def test_get_subject_stateOrProvinceName(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_stateOrProvinceName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "stateOrProvinceName")
        self.assertEqual(entries[0].get_value(), "Narnia")

    def test_get_subject_localityName(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_localityName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "localityName")
        self.assertEqual(entries[0].get_value(), "Funkytown")

    def test_get_subject_organizationName(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_organizationName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationName")
        self.assertEqual(entries[0].get_value(), "Anchor Testing")

    def test_get_subject_organizationUnitName(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_organizationalUnitName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationalUnitName")
        self.assertEqual(entries[0].get_value(), "testing")

    def test_get_subject_commonName(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_commonName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "commonName")
        self.assertEqual(entries[0].get_value(), "anchor.test")

    def test_get_subject_emailAddress(self):
        name = self.cert.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_pkcs9_emailAddress)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "emailAddress")
        self.assertEqual(entries[0].get_value(), "test@anchor.test")

    def test_get_issuer_countryName(self):
        name = self.cert.get_issuer()
        entries = name.get_entries_by_oid(x509_name.OID_countryName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "AU")

    def test_get_issuer_stateOrProvinceName(self):
        name = self.cert.get_issuer()
        entries = name.get_entries_by_oid(x509_name.OID_stateOrProvinceName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "stateOrProvinceName")
        self.assertEqual(entries[0].get_value(), "Some-State")

    def test_get_issuer_organizationName(self):
        name = self.cert.get_issuer()
        entries = name.get_entries_by_oid(x509_name.OID_organizationName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "organizationName")
        self.assertEqual(entries[0].get_value(), "Herp Derp plc")

    def test_get_issuer_commonName(self):
        name = self.cert.get_issuer()
        entries = name.get_entries_by_oid(x509_name.OID_commonName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "commonName")
        self.assertEqual(entries[0].get_value(), "herp.derp.plc")

    def test_set_subject(self):
        name = x509_name.X509Name()
        name.add_name_entry(x509_name.OID_countryName, 'UK')
        self.cert.set_subject(name)

        name = self.cert.get_subject()
        entries = name.get_entries_by_oid(x509_name.OID_countryName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "UK")

    def test_set_issuer(self):
        name = x509_name.X509Name()
        name.add_name_entry(x509_name.OID_countryName, 'UK')
        self.cert.set_issuer(name)

        name = self.cert.get_issuer()
        entries = name.get_entries_by_oid(x509_name.OID_countryName)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_name(), "countryName")
        self.assertEqual(entries[0].get_value(), "UK")

    def test_read_from_file(self):
        open_name = 'anchor.X509.certificate.open'
        f = io.StringIO(TestX509Cert.cert_data)
        with mock.patch(open_name, create=True) as mock_open:
            mock_open.return_value = f

            cert = certificate.X509Certificate.from_file("some_path")
            name = cert.get_subject()
            entries = name.get_entries_by_oid(x509_name.OID_countryName)
            self.assertEqual(entries[0].get_value(), "UK")

    def test_get_fingerprint(self):
        fp = self.cert.get_fingerprint()
        self.assertEqual(fp, '03C6B30446157984C28A3C97F1616B96'
                             '5DED16744573F203A4EA51AB1AFA1F10')

    def test_get_fingerprint_invalid_hash(self):
        with self.assertRaises(x509_errors.X509Error):
            self.cert.get_fingerprint('no_such_hash')

    def test_get_version(self):
        v = self.cert.get_version()
        self.assertEqual(v, 2)

    def test_set_version(self):
        self.cert.set_version(5)
        v = self.cert.get_version()
        self.assertEqual(v, 5)

    def test_get_not_before(self):
        val = self.cert.get_not_before()
        self.assertEqual(1441151225.0, val)

    def test_set_not_before(self):
        self.cert.set_not_before(0)  # seconds since epoch
        val = self.cert.get_not_before()
        self.assertEqual(0, val)

    def test_get_not_after(self):
        val = self.cert.get_not_after()
        self.assertEqual(1441237625.0, val)

    def test_set_not_after(self):
        self.cert.set_not_after(0)  # seconds since epoch
        val = self.cert.get_not_after()
        self.assertEqual(0, val)

    def test_get_extensions(self):
        exts = self.cert.get_extensions()
        self.assertEqual(3, len(exts))

    def test_add_extensions(self):
        bc = extension.X509ExtensionBasicConstraints()
        self.cert.add_extension(bc, 2)
        exts = self.cert.get_extensions()
        self.assertEqual(3, len(exts))

    def test_add_extensions_invalid(self):
        with self.assertRaises(x509_errors.X509Error):
            self.cert.add_extension("abcdef", 2)

    def test_verify_unknown_key(self):
        with self.assertRaises(x509_errors.X509Error):
            self.cert.verify("abc")

    def test_verify_signature_mismatch(self):
        alg = asn1_univ.ObjectIdentifier('1.2.3.4')
        self.cert._cert['signatureAlgorithm']['algorithm'] = alg
        with self.assertRaises(x509_errors.X509Error):
            self.cert.verify()
