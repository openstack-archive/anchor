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

import message_digest


class X509Error(Exception):
    def __init__(self, what):
        super(X509Error, self).__init__(what)


class X509CsrError(X509Error):
    def __init__(self, what):
        super(X509CsrError, self).__init__(what)


class X509CertificateError(X509Error):
    def __init__(self, what):
        super(X509CertificateError, self).__init__(what)


class X509Name(object):
    nid = {'C': backend._lib.NID_countryName,
           'SP': backend._lib.NID_stateOrProvinceName,
           'ST': backend._lib.NID_stateOrProvinceName,
           'stateOrProvinceName': backend._lib.NID_stateOrProvinceName,
           'L': backend._lib.NID_localityName,
           'localityName': backend._lib.NID_localityName,
           'O': backend._lib.NID_organizationName,
           'organizationName': backend._lib.NID_organizationName,
           'OU': backend._lib.NID_organizationalUnitName,
           'organizationUnitName': backend._lib.NID_organizationalUnitName,
           'CN': backend._lib.NID_commonName,
           'commonName': backend._lib.NID_commonName,
           'Email': backend._lib.NID_pkcs9_emailAddress,
           'emailAddress': backend._lib.NID_pkcs9_emailAddress,
           'serialNumber': backend._lib.NID_serialNumber,
           'SN': backend._lib.NID_surname,
           'surname': backend._lib.NID_surname,
           'GN': backend._lib.NID_givenName,
           'givenName': backend._lib.NID_givenName
           }

    class Entry():
        def __init__(self, obj):
            self._lib = backend._lib
            self._ffi = backend._ffi
            self._entry = obj

        def __str__(self):
            return "%s %s" % (self.get_name(), self.get_value())

        def __cmp__(self, other):
            data = str(other)
            asn1_str_1 = self._lib.ASN1_STRING_new()
            asn1_str_1 = self._ffi.gc(asn1_str_1, self._lib.ASN1_STRING_free)
            ret = self._lib.ASN1_STRING_set(asn1_str_1, data, len(data))
            if ret != 0:
                asn1_str_2 = self._lib.X509_NAME_ENTRY_get_string(self._entry)
                ret = self._lib.ASN1_STRING_cmp(asn1_str_1, asn1_str_2)
                return (ret == 1)
            raise X509Error("Could not setup ASN1 string data.")

        def get_name(self):
            asn1_obj = self._lib.X509_NAME_ENTRY_get_object(self._entry)
            buf = self._ffi.new('char[]', 1024)
            ret = self._lib.OBJ_obj2txt(buf, 1024, asn1_obj, 0)
            if ret == 0:
                raise X509Error("Could not convert ASN1_OBJECT to string.")
            return self._ffi.string(buf)

        def get_value(self):
            val = self._lib.X509_NAME_ENTRY_get_data(self._entry)
            data = self._lib.ASN1_STRING_data(val)
            return self._ffi.string(data)  # Encoding?

    def __init__(self, name_obj):
        # NOTE(tkelsey): we dont take ownership of the name obj
        self._lib = backend._lib
        self._ffi = backend._ffi
        self._name_obj = name_obj

    def __str__(self):
        # NOTE(tkelsey): we need to pass in a max size, so why not 1024
        val = self._lib.X509_NAME_oneline(self._name_obj, self._ffi.NULL, 1024)
        if val == self._ffi.NULL:
            raise X509Error("Could not convert X509_NAME to string.")

        val = self._ffi.gc(val, self._lib.OPENSSL_free)
        return self._ffi.string(val)

    def __len__(self):
        return self._lib.X509_NAME_entry_count(self._name_obj)

    def __getitem__(self, idx):
        if not (0 <= idx < self.entry_count()):
            raise IndexError("index out of range")
        ent = self._lib.X509_NAME_get_entry(self._name_obj, idx)
        return X509Name.Entry(ent)

    def __iter__(self):
        for i in xrange(self.entry_count()):
            yield self[i]

    def entry_count(self):
        return self._lib.X509_NAME_entry_count(self._name_obj)

    def get_entries_by_nid_name(self, nid_name):
        if nid_name not in X509Name.nid:
            raise X509Error("Unknown NID name: %s" % nid_name)

        out = []
        nid = X509Name.nid[nid_name]
        idx = self._lib.X509_NAME_get_index_by_NID(self._name_obj, nid, -1)
        while idx != -1:
            val = self._lib.X509_NAME_get_entry(self._name_obj, idx)
            if val != self._ffi.NULL:
                out.append(X509Name.Entry(val))

            idx = self._lib.X509_NAME_get_index_by_NID(self._name_obj,
                                                       nid, idx)
        return out


class X509Extension(object):
    def __init__(self, ext):
        self._lib = backend._lib
        self._ffi = backend._ffi
        self._ext = ext

    def __str__(self):
        return "%s %s" % (self.get_name(), self.get_value())

    def get_name(self):
        ext_obj = self._lib.X509_EXTENSION_get_object(self._ext)
        ext_nid = self._lib.OBJ_obj2nid(ext_obj)
        ext_name_str = self._lib.OBJ_nid2sn(ext_nid)
        return self._ffi.string(ext_name_str)

    def get_value(self):
        val = self._lib.X509_EXTENSION_get_data(self._ext)
        # internally its all just ASN1_STRINGs, but cffi checks.
        val = self._ffi.cast("ASN1_STRING*", val)
        data = self._lib.ASN1_STRING_data(val)
        return self._ffi.string(data)


class X509_csr(object):
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
        bio = backend._bytes_to_bio(data.encode('ascii'))
        ptr = self._ffi.new("X509_REQ **")
        ptr[0] = self._csrObj
        ret = self._lib.PEM_read_bio_X509_REQ(bio[0], ptr,
                                              self._ffi.NULL,
                                              self._ffi.NULL)
        if ret == self._ffi.NULL:
            raise X509CsrError("Could not read X509 CSR from PEM data.")

    def from_file(self, path, password=None):
        data = None
        with open(path, 'rb') as f:
            data = f.read()
        self.fromBuffer(data, password)

    def get_pubkey(self):
        pkey = self._lib.X509_REQ_get_pubkey(self._csrObj)
        if pkey == self._ffi.NULL:
            raise X509CsrError("Could not get pubkey from X509 CSR Object.")

        return pkey

    def get_subject(self):
        subs = self._lib.X509_REQ_get_subject_name(self._csrObj)
        if subs == self._ffi.NULL:
            raise X509CsrError("Could not get subject from X509 CSR Object.")

        return X509Name(subs)

    def get_extensions(self):
        # TODO(tkelsey): I assume the ext list copies data and this is safe
        # TODO(tkelsey): Error checking needed here
        ret = []
        exts = self._lib.X509_REQ_get_extensions(self._csrObj)
        num = self._lib.sk_X509_EXTENSION_num(exts)
        for i in range(0, num):
            ext = self._lib.sk_X509_EXTENSION_value(exts, i)
            ret.append(X509Extension(ext))
        self._lib.sk_X509_EXTENSION_free(exts)
        return ret


class X509_cert:
    def __init__(self):
        self._lib = backend._lib
        self._ffi = backend._ffi
        certObj = self._lib.X509_new()
        if certObj == self._ffi.NULL:
            raise X509CertificateError("Could not create X509 certifiacte "
                                       "object")

        self._certObj = certObj

    def __del__(self):
        if getattr(self, '_certObj', None):
            self._lib.X509_free(self._certObj)

    def _asn1_utctime(self, t):
        # asn1_utctime = self._lib.ASN1_UTCTIME_new()
        asn1_utctime = self._lib.ASN1_UTCTIME_set(self._ffi.NULL, t)
        if asn1_utctime == self._ffi.NULL:
            raise X509CertificateError("Could not create ASN1_UTCTIME object")

        return asn1_utctime

    def from_buffer(self, data):
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
        data = None
        with open(path, 'rb') as f:
            data = f.read()
        self.from_buffer(data)

    def save(self, path):
        bio = self._lib.BIO_new_file(path, "w")
        ret = self._lib.PEM_write_bio_X509(bio, self._certObj)
        self._lib.BIO_free(bio)

        if ret == 0:
            raise X509CertificateError("Could not write X509 certificate to "
                                       "disk as PEM data.")

    def set_version(self, v):
        ret = self._lib.X509_set_version(self._certObj, v)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "version.")

    def set_not_before(self, t):
        ansi1_utc = self._asn1_utctime(t)
        ret = self._lib.X509_set_notBefore(self._certObj, ansi1_utc)
        self._lib.ASN1_UTCTIME_free(ansi1_utc)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "not before time.")

    def set_not_after(self, t):
        ansi1_utc = self._asn1_utctime(t)
        ret = self._lib.X509_set_notAfter(self._certObj, ansi1_utc)
        self._lib.ASN1_UTCTIME_free(ansi1_utc)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "not after time.")

    def set_pubkey(self, pkey):
        # pkey should be an EVP_PKEY ssl type
        ret = self._lib.X509_set_pubkey(self._certObj, pkey)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "pubkey.")

    def get_subject(self):
        val = self._lib.X509_get_subject_name(self._certObj)
        if val == self._ffi.NULL:
            raise X509CsrError("Could not get subject from X509 certificate.")

        return X509Name(val)

    def set_subject(self, subject):
        # subject should be an X509Name class instance
        val = subject._name_obj
        ret = self._lib.X509_set_subject_name(self._certObj, val)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "subject.")

    def set_issuer(self, issuer):
        # issuer should be an X509Name class instance
        val = issuer._name_obj
        ret = self._lib.X509_set_issuer_name(self._certObj, val)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "issuer.")

    def get_issuer(self):
        val = self._lib.X509_get_issuer_name(self._certObj)
        if val == self._ffi.NULL:
            raise X509CsrError("Could not get subject from X509 certificate.")

        return X509Name(val)

    def set_serial_number(self, serial):
        asn1_int = self._lib.ASN1_INTEGER_new()
        ret = self._lib.ASN1_INTEGER_set(asn1_int, serial)
        if ret != 0:
            ret = self._lib.X509_set_serialNumber(self._certObj, asn1_int)
        self._lib.ASN1_INTEGER_free(asn1_int)
        if ret == 0:
            raise X509CertificateError("Could not set X509 certificate "
                                       "serial number.")

    def add_extension(self, ext, index):
        # ext should be X509Extension instance
        ret = self._lib.X509_add_ext(self._certObj, ext._ext, index)
        if ret == 0:
            raise X509CertificateError("Could not add X509 certificate "
                                       "extension.")

    def sign(self, key, md='sha1'):
        # key should be a EVP_PKEY, hash is a string
        mda = getattr(self._lib, "EVP_%s" % md, None)
        if mda is None:
            msg = 'X509 signing error: Unknown algorithm {a}'.format(a=md)
            raise X509CertificateError(msg)
        ret = self._lib.X509_sign(self._certObj, key, mda())
        if ret == 0:
            raise X509CertificateError("X509 signing error: Could not sign "
                                       " certificate.")

    def as_der(self):
        buf = None
        num = self._lib.i2d_X509(self._certObj, self._ffi.NULL)
        if num != 0:
            buf = self._ffi.new("unsigned char[]", num+1)
            buf_ptr = self._ffi.new("unsigned char**")
            buf_ptr[0] = buf
            num = self._lib.i2d_X509(self._certObj, buf_ptr)

        if num == 0:
            raise X509CertificateError("Could not encode X509 certificate "
                                       "as DER.")
        return buf

    def get_fingerprint(self, md='md5'):
        der = self.as_der()
        md = message_digest.MessageDigest(md)
        md.update(der)
        digest = md.final()
        digest = hex(md._octx_to_num(digest))[2:-1].upper()
        return digest


def load_pem_private_key(key_data, passwd=None):
    # TODO(tkelsey): look at using backend.read_private_key
    #

    lib = backend._lib
    ffi = backend._ffi
    data = backend._bytes_to_bio(key_data)

    evp_pkey = lib.EVP_PKEY_new()
    evp_pkey_ptr = ffi.new("EVP_PKEY**")
    evp_pkey_ptr[0] = evp_pkey
    evp_pkey = lib.PEM_read_bio_PrivateKey(data[0], evp_pkey_ptr,
                                           ffi.NULL, ffi.NULL)

    evp_pkey = ffi.gc(evp_pkey, lib.EVP_PKEY_free)
    return evp_pkey
