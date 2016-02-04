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

import binascii
import io

from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import univ as asn1_univ

from anchor.asn1 import rfc5280
from anchor.asn1 import rfc6402
from anchor import util
from anchor.X509 import errors
from anchor.X509 import extension
from anchor.X509 import name
from anchor.X509 import signature
from anchor.X509 import utils as x509_utils


OID_extensionRequest = asn1_univ.ObjectIdentifier('1.2.840.113549.1.9.14')


class X509CsrError(errors.X509Error):
    def __init__(self, what):
        super(X509CsrError, self).__init__(what)


class X509Csr(signature.SignatureMixin):
    """An X509 Certificate Signing Request."""
    def __init__(self, csr=None):
        if csr is None:
            self._csr = rfc6402.CertificationRequest()
        else:
            self._csr = csr

    @staticmethod
    def from_open_file(f, encoding='pem'):
        if encoding == 'pem':
            try:
                der_content = util.extract_pem(f.read())
            except IOError:
                raise X509CsrError("Could not read from source %s" % f)
            except Exception:
                raise X509CsrError(
                    "Data source not readable or not in PEM format")

            if not der_content:
                raise X509CsrError("No PEM data found")
        elif encoding == 'der':
            der_content = f.read()
        else:
            raise X509CsrError("Unknown encoding")

        try:
            csr = decoder.decode(der_content,
                                 asn1Spec=rfc6402.CertificationRequest())[0]
            return X509Csr(csr)
        except Exception:
            raise X509CsrError("Could not read X509 certificate from data.")

    @staticmethod
    def from_buffer(data, encoding='pem'):
        """Create this CSR from a buffer

        :param data: The data buffer
        """
        return X509Csr.from_open_file(io.BytesIO(data), encoding)

    @staticmethod
    def from_file(path, encoding='pem'):
        """Create this CSR from a file on disk

        :param path: Path to the file on disk
        """
        try:
            with open(path, 'r') as f:
                return X509Csr.from_open_file(f, encoding)
        except IOError:
            raise X509CsrError("Could not read file %s" % path)

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
                     if a['attrType'] == OID_extensionRequest]
        if len(ext_attrs) == 0:
            return []
        else:
            exts_der = ext_attrs[0]['attrValues'][0].asOctets()
            exts = decoder.decode(exts_der, asn1Spec=rfc5280.Extensions())[0]
            return [extension.construct_extension(e) for e in exts
                    if ext_type is None or e['extnID'] == ext_type._oid]

    def add_extension(self, new_ext):
        """Add a new extension or replace existing one."""
        if not isinstance(new_ext, extension.X509Extension):
            raise errors.X509Error("ext is not an anchor X509Extension")
        attributes = self.get_attributes()
        ext_attrs = [a for a in attributes
                     if a['attrType'] == OID_extensionRequest]
        if not ext_attrs:
            new_attr_index = len(attributes)
            attributes[new_attr_index] = None
            ext_attr = attributes[new_attr_index]
            ext_attr['attrType'] = OID_extensionRequest
            ext_attr['attrValues'] = None
            exts = rfc5280.Extensions()
        else:
            ext_attr = ext_attrs[0]
            exts = decoder.decode(ext_attr['attrValues'][0].asOctets(),
                                  asn1Spec=rfc5280.Extensions())[0]

        # the end is the default position
        new_ext_index = len(exts)
        # unless there's an existing extension with the same OID
        for i, ext_i in enumerate(exts):
            if ext_i['extnID'] == new_ext.get_oid():
                new_ext_index = i
                break

        exts[new_ext_index] = new_ext._ext

        ext_attr['attrValues'][0] = encoder.encode(exts)

    def get_subject_dns_ids(self):
        names = []
        for ext in self.get_extensions(extension.X509ExtensionSubjectAltName):
            for dns_id in ext.get_dns_ids():
                names.append(dns_id)
        return names

    def get_subject_ip_ids(self):
        names = []
        for ext in self.get_extensions(extension.X509ExtensionSubjectAltName):
            for ip in ext.get_ips():
                names.append(ip)
        return names

    def has_unknown_san_entries(self):
        for ext in self.get_extensions(extension.X509ExtensionSubjectAltName):
            if ext.has_unknown_entries():
                return True
        return False

    def get_public_key_algo(self):
        csr_info = self._csr['certificationRequestInfo']
        key_info = csr_info['subjectPublicKeyInfo']
        return key_info['algorithm']['algorithm']

    def get_public_key_size(self):
        return self._get_public_key().key_size

    def get_public_key(self):
        return self._get_public_key()

    def get_signing_algorithm(self):
        return self._get_signing_algorithm()

    def _get_signature(self):
        return x509_utils.bin_to_bytes(self._csr['signature'])

    def _get_signing_algorithm(self):
        return self._csr['signatureAlgorithm']['algorithm']

    def _get_public_key(self):
        csr_info = self._csr['certificationRequestInfo']
        key_info = csr_info['subjectPublicKeyInfo']
        return x509_utils.get_public_key_from_der(encoder.encode(key_info))

    def _get_bytes_to_sign(self):
        return encoder.encode(self._csr['certificationRequestInfo'])

    def _embed_signature_algorithm(self, algo_id):
        pass

    def _embed_signature(self, algo_id, signature):
        self._csr['signatureAlgorithm'] = algo_id
        self._csr['signature'] = "'%s'H" % (
            str(binascii.hexlify(signature).decode('ascii')),)
