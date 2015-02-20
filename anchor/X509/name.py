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


class X509Name(object):
    """An X509 Name object."""

    # NOTE(tkelsey): this is not exhaustive
    nid = {'C': backend._lib.NID_countryName,
           'countryName': backend._lib.NID_countryName,
           'SP': backend._lib.NID_stateOrProvinceName,
           'ST': backend._lib.NID_stateOrProvinceName,
           'stateOrProvinceName': backend._lib.NID_stateOrProvinceName,
           'L': backend._lib.NID_localityName,
           'localityName': backend._lib.NID_localityName,
           'O': backend._lib.NID_organizationName,
           'organizationName': backend._lib.NID_organizationName,
           'OU': backend._lib.NID_organizationalUnitName,
           'organizationalUnitName': backend._lib.NID_organizationalUnitName,
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
        """An X509 Name sub-entry object."""
        def __init__(self, obj):
            self._lib = backend._lib
            self._ffi = backend._ffi
            self._entry = obj

        def __str__(self):
            return "%s %s" % (self.get_name(), self.get_value())

        def get_name(self):
            """Get the name of this entry.

            :return: entry name as a python string
            """
            asn1_obj = self._lib.X509_NAME_ENTRY_get_object(self._entry)
            buf = self._ffi.new('char[]', 1024)
            ret = self._lib.OBJ_obj2txt(buf, 1024, asn1_obj, 0)
            if ret == 0:
                raise errors.X509Error("Could not convert ASN1_OBJECT to "
                                       "string.")
            return self._ffi.string(buf)

        def get_value(self):
            """Get the value of this entry.

            :return: entry value as a python string
            """
            val = self._lib.X509_NAME_ENTRY_get_data(self._entry)
            data = self._lib.ASN1_STRING_data(val)
            return self._ffi.string(data)  # Encoding?

    def __init__(self, name_obj=None):
        self._lib = backend._lib
        self._ffi = backend._ffi
        if name_obj is not None:
            self._name_obj = self._lib.X509_NAME_dup(name_obj)
            if self._name_obj == self._ffi.NULL:
                raise errors.X509Error("Failed to copy X509_NAME object.")
        else:
            self._name_obj = self._lib.X509_NAME_new()
            if self._name_obj == self._ffi.NULL:
                raise errors.X509Error("Failed to create X509_NAME object.")

    def __del__(self):
        self._lib.X509_NAME_free(self._name_obj)

    def __str__(self):
        # NOTE(tkelsey): we need to pass in a max size, so why not 1024
        val = self._lib.X509_NAME_oneline(self._name_obj, self._ffi.NULL, 1024)
        if val == self._ffi.NULL:
            raise errors.X509Error("Could not convert X509_NAME to string.")

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

    def add_name_entry(self, nid_name, text):
        """Add a name entry by its NID name."""
        if nid_name not in X509Name.nid:
            raise errors.X509Error("Unknown NID name: %s" % nid_name)

        nid = X509Name.nid[nid_name]
        ret = self._lib.X509_NAME_add_entry_by_NID(
            self._name_obj, nid,
            self._lib.MBSTRING_ASC,
            text, -1, -1, 0)

        if ret != 1:
            raise errors.X509Error("Failed to add name entry: '%s' '%s'" % (
                nid_name, text))

    def entry_count(self):
        """Get the number of entries in the name object."""
        return self._lib.X509_NAME_entry_count(self._name_obj)

    def get_entries_by_nid_name(self, nid_name):
        """Get a name entry corresponding to an NID name.

        :param nid_name: an NID name, chosen from the X509Name.nid table
        :return: An X509Name.Entry object
        """
        if nid_name not in X509Name.nid:
            raise errors.X509Error("Unknown NID name: %s" % nid_name)

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
