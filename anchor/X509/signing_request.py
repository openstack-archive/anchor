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

from __future__ import absolute_import

import io

from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import univ as asn1_univ
from pyasn1_modules import pem
from pyasn1_modules import rfc2314  # PKCS#10 / CSR
from pyasn1_modules import rfc2459  # X509

from anchor.X509 import errors
from anchor.X509 import extension
from anchor.X509 import name
from anchor.X509 import signature
from anchor.X509 import utils


OID_extensionRequest = asn1_univ.ObjectIdentifier('1.2.840.113549.1.9.14')


class X509CsrError(errors.X509Error):
    def __init__(self, what):
        super(X509CsrError, self).__init__(what)


class X509Csr(signature.SignatureMixin):
    """An X509 Certificate Signing Request."""
    def __init__(self, csr=None):
        if csr is None:
            self._csr = rfc2314.CertificationRequest()
        else:
            self._csr = csr

    @staticmethod
    def from_open_file(f):
        try:
            der_content = pem.readPemFromFile(
                f, startMarker='-----BEGIN CERTIFICATE REQUEST-----',
                endMarker='-----END CERTIFICATE REQUEST-----')
            csr = decoder.decode(der_content,
                                 asn1Spec=rfc2314.CertificationRequest())[0]
            return X509Csr(csr)
        except Exception:
            raise X509CsrError("Could not read X509 certificate from "
                               "PEM data.")

    @staticmethod
    def from_buffer(data):
        """Create this CSR from a buffer

        :param data: The data buffer
        """
        return X509Csr.from_open_file(io.StringIO(data))

    @staticmethod
    def from_file(path):
        """Create this CSR from a file on disk

        :param path: Path to the file on disk
        """
        with open(path, 'r') as f:
            return X509Csr.from_open_file(f)

    def get_pubkey(self):
        """Get the public key from the CSR

        :return: ASN.1 description of public key
        """
        return self._csr['certificationRequestInfo']['subjectPublicKeyInfo']

    def get_request_info(self):
        if self._csr['certificationRequestInfo'] is None:
            self._csr['certificationRequestInfo'] = None
        return self._csr['certificationRequestInfo']

    def get_subject(self):
        """Get the subject name field from the CSR

        :return: an X509Name object
        """
        ri = self.get_request_info()
        if ri['subject'] is None:
            ri['subject'] = None
            # setup first RDN sequence
            ri['subject'][0] = None

        subject = ri['subject'][0]
        return name.X509Name(subject)

    def set_subject(self, subject):
        if not isinstance(subject, name.X509Name):
            raise TypeError("subject must be an X509Name")
        ri = self.get_request_info()
        if ri['subject'] is None:
            ri['subject'] = None

        ri['subject'][0] = subject._name_obj

    def get_attributes(self):
        ri = self.get_request_info()
        if ri['attributes'] is None:
            ri['attributes'] = None
        return ri['attributes']

    def get_subject_cn(self):
        """Get the CN part of subject.

        :return subject's CN
        """
        subject = self.get_subject()
        cns = subject.get_entries_by_oid(name.OID_commonName)
        return [cn.get_value() for cn in cns]

    def get_extensions(self, ext_type=None):
        """Get the list of all X509 V3 Extensions on this CSR

        :return: a list of X509Extension objects
        """
        ext_attrs = [a for a in self.get_attributes()
                     if a['type'] == OID_extensionRequest]
        if len(ext_attrs) == 0:
            return []
        else:
            exts_der = ext_attrs[0]['vals'][0].asOctets()
            exts = decoder.decode(exts_der, asn1Spec=rfc2459.Extensions())[0]
            return [extension.construct_extension(e) for e in exts
                    if ext_type is None or e['extnID'] == ext_type._oid]

    def add_extension(self, new_ext):
        """Add a new extension or replace existing one."""
        if not isinstance(new_ext, extension.X509Extension):
            raise errors.X509Error("ext is not an anchor X509Extension")
        attributes = self.get_attributes()
        ext_attrs = [a for a in attributes
                     if a['type'] == OID_extensionRequest]
        if not ext_attrs:
            new_attr_index = len(attributes)
            attributes[new_attr_index] = None
            ext_attr = attributes[new_attr_index]
            ext_attr['type'] = OID_extensionRequest
            ext_attr['vals'] = None
            exts = rfc2459.Extensions()
        else:
            ext_attr = ext_attrs[0]
            exts = decoder.decode(ext_attr['vals'][0].asOctets(),
                                  asn1Spec=rfc2459.Extensions())[0]

        # the end is the default position
        new_ext_index = len(exts)
        # unless there's an existing extension with the same OID
        for i, ext_i in enumerate(exts):
            if ext_i['extnID'] == new_ext.get_oid():
                new_ext_index = i
                break

        exts[new_ext_index] = new_ext._ext

        ext_attr['vals'][0] = encoder.encode(exts)

    def _get_signature(self):
        return utils.bin_to_bytes(self._csr['signature'])

    def _get_signing_algorithm(self):
        return self._csr['signatureAlgorithm']['algorithm']

    def _get_public_key(self):
        csr_info = self._csr['certificationRequestInfo']
        key_info = csr_info['subjectPublicKeyInfo']
        csr_public_key = key_info['subjectPublicKey']
        return utils.get_public_key_from_der(
            utils.bin_to_bytes(csr_public_key))

    def _get_bytes_to_sign(self):
        return encoder.encode(self._csr['certificationRequestInfo'])

    def _embed_signature_algorithm(self, algo_id):
        pass

    def _embed_signature(self, algo_id, signature):
        self._csr['signatureAlgorithm'] = algo_id
        self._csr['signature'] = "'%s'B" % (utils.bytes_to_bin(signature),)
