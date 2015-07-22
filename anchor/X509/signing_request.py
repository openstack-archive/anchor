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

from anchor.X509 import certificate
from anchor.X509 import errors
from anchor.X509 import extension
from anchor.X509 import name


OID_extensionRequest = asn1_univ.ObjectIdentifier('1.2.840.113549.1.9.14')


class X509CsrError(errors.X509Error):
    def __init__(self, what):
        super(X509CsrError, self).__init__(what)


class X509Csr(object):
    """An X509 Certificate Signing Request."""
    def __init__(self, csr=None):
        if csr is None:
            self._csr = rfc2314.CertificationRequest()
        else:
            self._csr = csr

    @staticmethod
    def from_open_file(f):
        try:
            der_content = pem.readPemFromFile(f, startMarker='-----BEGIN CERTIFICATE REQUEST-----', endMarker='-----END CERTIFICATE REQUEST-----')
            csr = decoder.decode(der_content, asn1Spec=rfc2314.CertificationRequest())[0]
            return X509Csr(csr)
        except Exception:
            raise X509CsrError("Could not read X509 certificate from "
                               "PEM data.")

    @staticmethod
    def from_buffer(data):
        """Create this CSR from a buffer

        :param data: The data buffer
        """
        return X509Csr.from_open_file(io.BytesIO(data))

    @staticmethod
    def from_file(path):
        """Create this CSR from a file on disk

        :param path: Path to the file on disk
        """
        with open(path, 'rb') as f:
            return X509Csr.from_open_file(f)

    def get_pubkey(self):
        """Get the public key from the CSR

        :return: an OpenSSL EVP_PKEY object
        """
        return self._csr['certificationRequestInfo']['subjectPublicKeyInfo']

    def get_subject(self):
        """Get the subject name field from the CSR

        :return: an X509Name object
        """
        subject = self._csr['certificationRequestInfo']['subject'][0]
        return name.X509Name(subject)

    def get_attributes(self):
        return self._csr['certificationRequestInfo']['attributes']

    def get_extensions(self):
        """Get the list of all X509 V3 Extensions on this CSR

        :return: a list of X509Extension objects
        """
        ext_attrs = [a for a in self.get_attributes() if a['type'] == OID_extensionRequest]
        if len(ext_attrs) == 0:
            return []
        else:
            exts_der = ext_attrs[0]['vals'][0].asOctets()
            exts = decoder.decode(exts_der, asn1Spec=rfc2459.Extensions())[0]
            return [extension.X509Extension(e) for e in exts]
