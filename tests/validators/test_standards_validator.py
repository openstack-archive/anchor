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

import unittest

import mock
from pyasn1.codec.der import encoder
from pyasn1_modules import rfc2459

from anchor.asn1 import rfc5280
from anchor.validators import errors
from anchor.validators import standards
from anchor.X509 import extension
from anchor.X509 import name
from anchor.X509 import signing_request
import tests


class TestStandardsValidator(tests.DefaultRequestMixin, unittest.TestCase):
    def test_passing(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_sample_bytes)
        standards.standards_compliance(csr=csr)


class TestExtensionDuplicates(unittest.TestCase):
    def test_no_extensions(self):
        csr = signing_request.X509Csr()
        standards._no_extension_duplicates(csr)

    def test_no_duplicates(self):
        csr = signing_request.X509Csr()
        ext = extension.X509ExtensionSubjectAltName()
        csr.add_extension(ext)
        standards._no_extension_duplicates(csr)

    def test_with_duplicates(self):
        csr = signing_request.X509Csr()
        ext = extension.X509ExtensionSubjectAltName()
        ext.add_dns_id('example.com')
        exts = rfc5280.Extensions()
        exts[0] = ext._ext
        exts[1] = ext._ext
        # Anchor doesn't allow this normally, so tests need to cheat
        attrs = csr.get_attributes()
        attrs[0] = None
        attrs[0]['attrType'] = signing_request.OID_extensionRequest
        attrs[0]['attrValues'] = None
        attrs[0]['attrValues'][0] = encoder.encode(exts)
        with self.assertRaises(errors.ValidationError):
            standards._no_extension_duplicates(csr)


class TestExtensionCriticalFlags(unittest.TestCase):
    def test_no_subject_san_not_critical(self):
        csr = signing_request.X509Csr()
        ext = extension.X509ExtensionSubjectAltName()
        ext.set_critical(False)
        ext.add_dns_id('example.com')
        csr.add_extension(ext)
        with self.assertRaises(errors.ValidationError):
            standards._critical_flags(csr)

    def test_no_subject_san_critical(self):
        csr = signing_request.X509Csr()
        ext = extension.X509ExtensionSubjectAltName()
        ext.set_critical(True)
        ext.add_dns_id('example.com')
        csr.add_extension(ext)
        standards._critical_flags(csr)

    def test_with_subject_san_not_critical(self):
        csr = signing_request.X509Csr()
        subject = name.X509Name()
        subject.add_name_entry(name.OID_commonName, "example.com")
        csr.set_subject(subject)
        ext = extension.X509ExtensionSubjectAltName()
        ext.set_critical(False)
        ext.add_dns_id('example.com')
        csr.add_extension(ext)
        standards._critical_flags(csr)

    def test_basic_constraints_not_critical(self):
        csr = signing_request.X509Csr()
        ext = extension.X509ExtensionBasicConstraints()
        ext.set_critical(False)
        csr.add_extension(ext)
        with self.assertRaises(errors.ValidationError):
            standards._critical_flags(csr)

    def test_basic_constraints_critical(self):
        csr = signing_request.X509Csr()
        ext = extension.X509ExtensionBasicConstraints()
        ext.set_critical(True)
        csr.add_extension(ext)
        standards._critical_flags(csr)


class TestValidDomains(unittest.TestCase):
    def _create_csr_with_domain_san(self, domain):
        csr = signing_request.X509Csr()
        ext = extension.X509ExtensionSubjectAltName()
        # add without validation - we want to test the _valid_domains
        # here, not adding
        ext.add_dns_id(domain, validate=False)
        csr.add_extension(ext)
        return csr

    def test_all_valid(self):
        csr = self._create_csr_with_domain_san('a-123.example.com')
        standards._valid_domains(csr)

    def test_all_valid_trailing_dot(self):
        csr = self._create_csr_with_domain_san('a-123.example.com.')
        standards._valid_domains(csr)

    def test_too_long(self):
        csr = self._create_csr_with_domain_san(
            'very-long-label-over-63-characters-'
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com')
        with self.assertRaises(errors.ValidationError):
            standards._valid_domains(csr)

    def test_beginning_hyphen(self):
        csr = self._create_csr_with_domain_san('-label.example.com.')
        with self.assertRaises(errors.ValidationError):
            standards._valid_domains(csr)

    def test_trailing_hyphen(self):
        csr = self._create_csr_with_domain_san('label-.example.com.')
        with self.assertRaises(errors.ValidationError):
            standards._valid_domains(csr)

    def test_san_space(self):
        # valid domain, but not in CSRs
        csr = self._create_csr_with_domain_san(' ')
        with self.assertRaises(errors.ValidationError):
            standards._valid_domains(csr)

    def test_wildcard(self):
        csr = self._create_csr_with_domain_san('*.example.com')
        standards._valid_domains(csr)

    def test_wildcard_middle(self):
        csr = self._create_csr_with_domain_san('foo.*.example.com')
        with self.assertRaises(errors.ValidationError):
            standards._valid_domains(csr)

    def test_wildcard_partial(self):
        csr = self._create_csr_with_domain_san('foo*.example.com')
        with self.assertRaises(errors.ValidationError):
            standards._valid_domains(csr)


class TestCsrSignature(tests.DefaultRequestMixin, unittest.TestCase):
    def test_csr_signature(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_sample_bytes)
        self.assertIsNone(standards._csr_signature(csr=csr))

    def test_csr_signature_bad_sig(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_sample_bytes)
        with mock.patch.object(signing_request.X509Csr, '_get_signature',
                               return_value=(b'A'*49)):
            with self.assertRaisesRegexp(errors.ValidationError,
                                         "Signature on the CSR is not valid"):
                standards._csr_signature(csr=csr)

    def test_csr_signature_bad_algo(self):
        csr = signing_request.X509Csr.from_buffer(self.csr_sample_bytes)
        with mock.patch.object(signing_request.X509Csr,
                               '_get_signing_algorithm',
                               return_value=rfc2459.id_dsa_with_sha1):
            with self.assertRaisesRegexp(errors.ValidationError,
                                         "Signature on the CSR is not valid"):
                standards._csr_signature(csr=csr)
