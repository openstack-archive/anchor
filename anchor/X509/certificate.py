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

from cryptography.hazmat.backends.openssl import backend

from anchor.X509 import errors
from anchor.X509 import message_digest
from anchor.X509 import name
from anchor.X509 import utils


class X509CertificateError(errors.X509Error):
    """Specific error for X509 certificate operations."""
    def __init__(self, what):
        super(X509CertificateError, self).__init__(what)


class X509Extension(object):
    """An X509 V3 Certificate extension."""
    def __init__(self, ext):
        self._lib = backend._lib
        self._ffi = backend._ffi
        self._ext = ext

    def __str__(self):
        return "%s %s" % (self.get_name(), self.get_value())

    def get_name(self):
        """Get the extension name as a python string."""
        ext_obj = self._lib.X509_EXTENSION_get_object(self._ext)
        ext_nid = self._lib.OBJ_obj2nid(ext_obj)
        ext_name_str = self._lib.OBJ_nid2sn(ext_nid)
        return self._ffi.string(ext_name_str)

    def get_value(self):
        """Get the extension value as a python string."""
        bio = self._lib.BIO_new(self._lib.BIO_s_mem())
        bio = self._ffi.gc(bio, self._lib.BIO_free)
        self._lib.X509V3_EXT_print(bio, self._ext, 0, 0)
        size = 1024
        data = self._ffi.new("char[]", size)
        self._lib.BIO_gets(bio, data, size)
        return self._ffi.string(data)


class X509Certificate(object):
    """X509 certificate class."""
    def __init__(self):
        self._lib = backend._lib
        self._ffi = backend._ffi
        certObj = self._lib.X509_new()
        if certObj == self._ffi.NULL:
            raise X509CertificateError("Could not create X509 certifiacte "
                                       "object")  # pragma: no cover

        self._certObj = certObj

    def __del__(self):
        if getattr(self, '_certObj', None):
            self._lib.X509_free(self._certObj)

    def from_buffer(self, data):
        """Build this X509 object from a data buffer in memory.

        :param data: A data buffer
        """
        bio = backend._bytes_to_bio(data.encode('ascii'))

        # NOTE(tkelsey): some versions of OpenSSL dont re-use the cert object
        # properly, so free it and use the new one
        #
        certObj = self._lib.PEM_read_bio_X509(bio[0],
                                              self._ffi.NULL,
                                              self._ffi.NULL,
                                              self._ffi.NULL)
        if certObj == self._ffi.NULL:
            raise X509CertificateError("Could not read X509 certificate from "
                                       "PEM data.")

        self._lib.X509_free(self._certObj)
        self._certObj = certObj

    def from_file(self, path):
        """Build this X509 certificate object from a data file on disk.

        :param path: A data buffer
        """
        data = None
        with open(path, 'rb') as f:
            data = f.read()
        self.from_buffer(data)

    def save(self, path):
        """Save this X509 certificate object to a file on disk.

        :param path: Output file path
        """
        bio = self._lib.BIO_new_file(path.encode('ascii', 'ignore'), "w")
        ret = self._lib.PEM_write_bio_X509(bio, self._certObj)
        self._lib.BIO_free(bio)

        if ret == 0:
            raise X509CertificateError("Could not write X509 certificate to "
                                       "disk as PEM data.")  # pragma: no cover

    def set_version(self, v):
        """Set the version of this X509 certificate object.

        :param v: The version
        """
        ret = self._lib.X509_set_version(self._certObj, v)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "version.")  # pragma: no cover

    def get_version(self):
        """Get the version of this X509 certificate object."""
        return self._lib.X509_get_version(self._certObj)

    def set_not_before(self, t):
        """Set the 'not before' date field.

        :param t: time in seconds since the epoch
        """
        asn1_time = utils.timestamp_to_asn1_time(t)
        ret = self._lib.X509_set_notBefore(self._certObj, asn1_time)
        self._lib.ASN1_TIME_free(asn1_time)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "not before time.")  # pragma: no cover

    def get_not_before(self):
        """Get the 'not before' date field as seconds since the epoch."""
        not_before = self._lib.X509_get_notBefore(self._certObj)
        return utils.asn1_time_to_timestamp(not_before)

    def set_not_after(self, t):
        """Set the 'not after' date field.

        :param t: time in seconds since the epoch
        """
        asn1_time = utils.timestamp_to_asn1_time(t)
        ret = self._lib.X509_set_notAfter(self._certObj, asn1_time)
        self._lib.ASN1_TIME_free(asn1_time)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "not after time.")  # pragma: no cover

    def get_not_after(self):
        """Get the 'not after' date field as seconds since the epoch."""
        not_after = self._lib.X509_get_notAfter(self._certObj)
        return utils.asn1_time_to_timestamp(not_after)

    def set_pubkey(self, pkey):
        """Set the public key field.

        :param pkey: The public key, an EVP_PKEY ssl type
        """
        ret = self._lib.X509_set_pubkey(self._certObj, pkey)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "pubkey.")  # pragma: no cover

    def get_subject(self):
        """Get the subject name field value.

        :return: An X509Name object instance
        """
        val = self._lib.X509_get_subject_name(self._certObj)
        if val == self._ffi.NULL:
            raise X509CertificateError("Could not get subject from X509 "
                                       "certificate.")  # pragma: no cover

        return name.X509Name(val)

    def set_subject(self, subject):
        """Set the subject name filed value.

        :param subject: An X509Name object instance
        """
        val = subject._name_obj
        ret = self._lib.X509_set_subject_name(self._certObj, val)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "subject.")  # pragma: no cover

    def set_issuer(self, issuer):
        """Set the issuer name field value.

        :param issuer: An X509Name object instance
        """
        val = issuer._name_obj
        ret = self._lib.X509_set_issuer_name(self._certObj, val)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "issuer.")  # pragma: no cover

    def get_issuer(self):
        """Get the issuer name field value.

        :return: An X509Name object instance
        """
        val = self._lib.X509_get_issuer_name(self._certObj)
        if val == self._ffi.NULL:
            raise X509CertificateError("Could not get subject from X509 "
                                       "certificate.")  # pragma: no cover
        return name.X509Name(val)

    def set_serial_number(self, serial):
        """Set the serial number

        The serial number is a 32 bit integer value that should be unique to
        each certificate issued by a given certificate authority.

        :param serial: The serial number, 32 bit integer
        """
        asn1_int = self._lib.ASN1_INTEGER_new()
        ret = self._lib.ASN1_INTEGER_set(asn1_int, serial)
        if ret != 0:
            ret = self._lib.X509_set_serialNumber(self._certObj, asn1_int)
        self._lib.ASN1_INTEGER_free(asn1_int)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "serial number.")  # pragma: no cover

    def add_extension(self, ext, index):
        """Add an X509 V3 Certificate extension.

        :param ext: An X509Extension instance
        :param index: The index of the extension
        """
        ret = self._lib.X509_add_ext(self._certObj, ext._ext, index)
        if ret == 0:
            raise X509CertificateError("Could not add X509 certificate "
                                       "extension.")  # pragma: no cover

    def sign(self, key, md='sha1'):
        """Sign the X509 certificate with a key using a message digest algorithm

        :param key: The signing key, an EVP_PKEY OpenSSL object
        :param md: The name of a message digest algorithm to use, it must be
                   valid and known to OpenSSL, possible values are
                   - md5
                   - sha1
                   - sha256
        """
        mda = getattr(self._lib, "EVP_%s" % md, None)
        if mda is None:
            msg = 'X509 signing error: Unknown algorithm {a}'.format(a=md)
            raise X509CertificateError(msg)
        ret = self._lib.X509_sign(self._certObj, key, mda())
        if ret == 0:
            raise X509CertificateError("X509 signing error: Could not sign "
                                       " certificate.")  # pragma: no cover

    def as_der(self):
        """Return this X509 certificate as DER encoded data."""
        buf = None
        num = self._lib.i2d_X509(self._certObj, self._ffi.NULL)
        if num != 0:
            buf = self._ffi.new("unsigned char[]", num + 1)
            buf_ptr = self._ffi.new("unsigned char**")
            buf_ptr[0] = buf
            num = self._lib.i2d_X509(self._certObj, buf_ptr)
        else:
            raise X509CertificateError("Could not encode X509 certificate "
                                       "as DER.")  # pragma: no cover
        return buf

    def get_fingerprint(self, md='md5'):
        """Get the fingerprint of this X509 certifiacte.

        :param md: The message digest algorthim used to compute the fingerprint
        :return: The fingerprint encoded as a hex string
        """
        der = self.as_der()
        md = message_digest.MessageDigest(md)
        md.update(der)
        return md.final()
