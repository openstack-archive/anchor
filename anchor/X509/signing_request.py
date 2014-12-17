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

from cryptography.hazmat.backends.openssl import backend

import errors
import certificate
import name


class X509CsrError(errors.X509Error):
    def __init__(self, what):
        super(X509CsrError, self).__init__(what)


class X509Csr(object):
    """An X509 Certificate Signing Request"""
    def __init__(self):
        self._lib = backend._lib
        self._ffi = backend._ffi
        csrObj = self._lib.X509_REQ_new()
        if csrObj == self._ffi.NULL:
            raise X509CsrError("Could not create X509 CSR Object.")

        self._csrObj = csrObj

    def __del__(self):
        if getattr(self, '_csrObj', None):
            self._lib.X509_REQ_free(self._csrObj)

    def from_buffer(self, data, password=None):
        """Create this CSR from a buffer
        :param data: The data buffer
        :param password: decryption password, if needed
        """
        bio = backend._bytes_to_bio(data.encode('ascii'))
        ptr = self._ffi.new("X509_REQ **")
        ptr[0] = self._csrObj
        ret = self._lib.PEM_read_bio_X509_REQ(bio[0], ptr,
                                              self._ffi.NULL,
                                              self._ffi.NULL)
        if ret == self._ffi.NULL:
            raise X509CsrError("Could not read X509 CSR from PEM data.")

    def from_file(self, path, password=None):
        """Create this CSR from a file on disk
        :param path: Path to the file on disk
        :param password: decryption password, if needed
        """
        data = None
        with open(path, 'rb') as f:
            data = f.read()
        self.fromBuffer(data, password)

    def get_pubkey(self):
        """Get the public key from the CSR
        :return: an OpenSSL EVP_PKEY object
        """
        pkey = self._lib.X509_REQ_get_pubkey(self._csrObj)
        if pkey == self._ffi.NULL:
            raise X509CsrError("Could not get pubkey from X509 CSR Object.")

        return pkey

    def get_subject(self):
        """Get the subject name field from the CSR
        :return: an X509Name object
        """
        subs = self._lib.X509_REQ_get_subject_name(self._csrObj)
        if subs == self._ffi.NULL:
            raise X509CsrError("Could not get subject from X509 CSR Object.")

        return name.X509Name(subs)

    def get_extensions(self):
        """Get the list of all X509 V3 Extensions on this CSR
        :return: a list of X509Extension objects
        """
        # TODO(tkelsey): I assume the ext list copies data and this is safe
        # TODO(tkelsey): Error checking needed here
        ret = []
        exts = self._lib.X509_REQ_get_extensions(self._csrObj)
        num = self._lib.sk_X509_EXTENSION_num(exts)
        for i in range(0, num):
            ext = self._lib.sk_X509_EXTENSION_value(exts, i)
            ret.append(certificate.X509Extension(ext))
        self._lib.sk_X509_EXTENSION_free(exts)
        return ret
