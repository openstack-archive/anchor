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

import mock
from pyasn1.type import univ as asn1_univ

from anchor import errors
from anchor import signers
from anchor.signers import cryptography_io
from anchor.signers import pkcs11
from anchor import util
from anchor.X509 import certificate
from anchor.X509 import extension
from anchor.X509 import signing_request
from anchor.X509 import utils
import tests


class UnknownExtension(extension.X509Extension):
    _oid = asn1_univ.ObjectIdentifier("1.2.3.4")
    spec = asn1_univ.Null


class SigningBackendExtensions(tests.DefaultConfigMixin,
                               tests.DefaultRequestMixin, unittest.TestCase):
    def test_copy_good_extensions(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_sample_bytes)
        ext = extension.X509ExtensionSubjectAltName()
        ext.add_dns_id("example.com")
        csr.add_extension(ext)

        pem = signers.sign_generic(csr, self.sample_conf_ca['default_ca'],
                                   'RSA', lambda x: b"")
        cert = certificate.X509Certificate.from_buffer(pem)
        self.assertEqual(1, len(cert.get_extensions(
            extension.X509ExtensionSubjectAltName)))

    def test_ignore_unknown_extensions(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_sample_bytes)
        ext = UnknownExtension()
        csr.add_extension(ext)

        pem = signers.sign_generic(csr, self.sample_conf_ca['default_ca'],
                                   'RSA', lambda x: b"")
        cert = certificate.X509Certificate.from_buffer(pem)
        self.assertEqual(0, len(cert.get_extensions(UnknownExtension)))

    def test_fail_critical_unknown_extensions(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_sample_bytes)
        ext = UnknownExtension()
        ext.set_critical(True)
        csr.add_extension(ext)

        with self.assertRaises(signers.SigningError):
            signers.sign_generic(csr, self.sample_conf_ca['default_ca'],
                                 'RSA', lambda x: b"")


class TestCryptographyBackend(tests.DefaultConfigMixin,
                              tests.DefaultRequestMixin, unittest.TestCase):
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

    def test_sign_bad_md(self):
        key = utils.get_private_key_from_pem(self.key_rsa_data)
        with self.assertRaises(signers.SigningError):
            cryptography_io.make_signer(key, "BAD", "RSA")

    def test_sign_bad_key(self):
        with self.assertRaises(signers.SigningError):
            cryptography_io.make_signer("BAD", "sha256", "RSA")


class TestPKCSBackend(unittest.TestCase):
    def setUp(self):
        self.good_conf = {
            "cert_path": "tests/CA/root-ca.crt",
            "output_path": "/somepath",
            "signing_hash": "sha256",
            "valid_hours": 24,
            "slot": 5,
            "pin": "somepin",
            "key_id": "aabbccddeeff",
            "pkcs11_path": "/somepath/library.so",
            }

    def test_conf_checks_package(self):
        with mock.patch.object(util, 'check_file_exists', return_value=True):
            with mock.patch.object(pkcs11, 'import_pkcs',
                                   side_effect=ImportError()):
                with self.assertRaises(errors.ConfigValidationException):
                    pkcs11.conf_validator("name", self.good_conf)

    def test_conf_checks_fields(self):
        for key in self.good_conf:
            conf = self.good_conf.copy()
            del conf[key]
            with self.assertRaises(errors.ConfigValidationException):
                pkcs11.conf_validator("name", conf)

    def test_conf_checks_file_permissions(self):
        with mock.patch.object(util, 'check_file_exists', return_value=False):
            with self.assertRaises(errors.ConfigValidationException):
                pkcs11.conf_validator("name", self.good_conf)

    def test_conf_checks_library_loading(self):
        class MockExc(Exception):
            pass

        lib = mock.Mock()
        lib.load.side_effect = MockExc()
        mod = mock.Mock()
        mod.PyKCS11Error = MockExc
        mod.PyKCS11Lib.return_value = lib

        with mock.patch.object(util, 'check_file_exists', return_value=True):
            with mock.patch.object(pkcs11, 'import_pkcs', return_value=mod):
                with self.assertRaises(errors.ConfigValidationException):
                    pkcs11.conf_validator("name", self.good_conf)

    def test_conf_checks_valid_slot(self):
        class MockExc(Exception):
            pass

        lib = mock.Mock()
        lib.getSlotList.return_value = [4, 6]
        mod = mock.Mock()
        mod.PyKCS11Error = MockExc
        mod.PyKCS11Lib.return_value = lib

        with mock.patch.object(util, 'check_file_exists', return_value=True):
            with mock.patch.object(pkcs11, 'import_pkcs', return_value=mod):
                with self.assertRaises(errors.ConfigValidationException):
                    pkcs11.conf_validator("name", self.good_conf)

    def test_conf_checks_valid_pin(self):
        class MockExc(Exception):
            pass

        session = mock.Mock()
        session.login.side_effect = MockExc()
        lib = mock.Mock()
        lib.getSlotList.return_value = [self.good_conf['slot']]
        lib.openSession.return_value = session
        mod = mock.Mock()
        mod.PyKCS11Error = MockExc
        mod.PyKCS11Lib.return_value = lib

        with mock.patch.object(util, 'check_file_exists', return_value=True):
            with mock.patch.object(pkcs11, 'import_pkcs', return_value=mod):
                with self.assertRaises(errors.ConfigValidationException):
                    pkcs11.conf_validator("name", self.good_conf)

    def test_conf_allows_valid(self):
        session = mock.Mock()
        lib = mock.Mock()
        lib.getSlotList.return_value = [self.good_conf['slot']]
        lib.openSession.return_value = session
        mod = mock.Mock()
        mod.PyKCS11Lib.return_value = lib

        with mock.patch.object(util, 'check_file_exists', return_value=True):
            with mock.patch.object(pkcs11, 'import_pkcs', return_value=mod):
                pkcs11.conf_validator("name", self.good_conf)

    def test_make_signer_fails(self):
        with mock.patch.object(pkcs11, 'make_signer',
                               side_effect=signers.SigningError):
            with self.assertRaises(signers.SigningError):
                pkcs11.sign(mock.Mock(), self.good_conf)

    def test_sign_login_fails(self):
        class MockExc(Exception):
            pass

        session = mock.Mock()
        session.login.side_effect = MockExc()
        lib = mock.Mock()
        lib.openSession.return_value = session
        mod = mock.Mock()
        mod.PyKCS11Error = MockExc
        mod.PyKCS11Lib.return_value = lib

        with mock.patch.object(pkcs11, 'import_pkcs', return_value=mod):
            with self.assertRaisesRegexp(signers.SigningError,
                                         "pkcs11 session"):
                pkcs11.sign(mock.Mock(), self.good_conf)

    def test_sign_key_missing(self):
        class MockExc(Exception):
            pass

        session = mock.Mock()
        session.findObjects.return_value = []
        lib = mock.Mock()
        lib.openSession.return_value = session
        mod = mock.Mock()
        mod.PyKCS11Lib.return_value = lib

        with mock.patch.object(pkcs11, 'import_pkcs', return_value=mod):
            with self.assertRaisesRegexp(signers.SigningError,
                                         "requested key"):
                pkcs11.sign(mock.Mock(), self.good_conf)

    def test_sign_bad_hash(self):
        session = mock.Mock()
        session.findObjects.return_value = [object()]
        lib = mock.Mock()
        lib.openSession.return_value = session
        mod = mock.Mock()
        mod.PyKCS11Lib.return_value = lib
        self.good_conf['signing_hash'] = 'unknown'

        with mock.patch.object(pkcs11, 'import_pkcs', return_value=mod):
            with self.assertRaisesRegexp(signers.SigningError,
                                         "hash is not supported"):
                pkcs11.sign(mock.Mock(), self.good_conf)

    def test_working_signer(self):
        res = b"123"

        session = mock.Mock()
        session.findObjects.return_value = [object()]
        session.sign.return_value = res
        lib = mock.Mock()
        lib.openSession.return_value = session
        mod = mock.Mock()
        mod.PyKCS11Lib.return_value = lib

        with mock.patch.object(pkcs11, 'import_pkcs', return_value=mod):
            signer = pkcs11.make_signer((1, 2, 3), self.good_conf['slot'],
                                        self.good_conf['pin'],
                                        self.good_conf['pkcs11_path'],
                                        self.good_conf['signing_hash'].upper())
            self.assertEqual(res, signer(b"data"))
