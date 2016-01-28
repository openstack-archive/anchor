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

from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import error as asn1_error
from pyasn1.type import univ as asn1_univ
from pyasn1_modules import rfc2459

from anchor.X509 import errors

OID_commonName = rfc2459.id_at_commonName
OID_localityName = rfc2459.id_at_localityName
OID_stateOrProvinceName = rfc2459.id_at_stateOrProvinceName
OID_organizationName = rfc2459.id_at_organizationName
OID_organizationalUnitName = rfc2459.id_at_organizationalUnitName
OID_countryName = rfc2459.id_at_countryName
OID_pkcs9_emailAddress = rfc2459.emailAddress
OID_surname = rfc2459.id_at_sutname
OID_givenName = rfc2459.id_at_givenName

name_oids = {
    rfc2459.id_at_name: rfc2459.X520name,
    rfc2459.id_at_sutname: rfc2459.X520name,
    rfc2459.id_at_givenName: rfc2459.X520name,
    rfc2459.id_at_initials: rfc2459.X520name,
    rfc2459.id_at_generationQualifier: rfc2459.X520name,
    rfc2459.id_at_commonName: rfc2459.X520CommonName,
    rfc2459.id_at_localityName: rfc2459.X520LocalityName,
    rfc2459.id_at_stateOrProvinceName: rfc2459.X520StateOrProvinceName,
    rfc2459.id_at_organizationName: rfc2459.X520OrganizationName,
    rfc2459.id_at_organizationalUnitName: rfc2459.X520OrganizationalUnitName,
    rfc2459.id_at_title: rfc2459.X520Title,
    rfc2459.id_at_dnQualifier: rfc2459.X520dnQualifier,
    rfc2459.id_at_countryName: rfc2459.X520countryName,
    rfc2459.emailAddress: rfc2459.Pkcs9email,
}

code_names = {
    rfc2459.id_at_commonName: "CN",
    rfc2459.id_at_localityName: "L",
    rfc2459.id_at_stateOrProvinceName: "ST",
    rfc2459.id_at_organizationName: "O",
    rfc2459.id_at_organizationalUnitName: "OU",
    rfc2459.id_at_countryName: "C",
    rfc2459.id_at_givenName: "GN",
    rfc2459.id_at_sutname: "SN",
    rfc2459.emailAddress: "emailAddress",
}

short_names = {
    rfc2459.id_at_commonName: "commonName",
    rfc2459.id_at_localityName: "localityName",
    rfc2459.id_at_stateOrProvinceName: "stateOrProvinceName",
    rfc2459.id_at_organizationName: "organizationName",
    rfc2459.id_at_organizationalUnitName: "organizationalUnitName",
    rfc2459.id_at_countryName: "countryName",
    rfc2459.id_at_givenName: "givenName",
    rfc2459.id_at_sutname: "surname",
    rfc2459.emailAddress: "emailAddress",
}


class X509Name(object):
    """An X509 Name object."""

    class Entry():
        """An X509 Name sub-entry object."""
        def __init__(self, obj):
            self._obj = obj

        def __str__(self):
            return "%s: %s" % (self.get_name(), self.get_value())

        def get_oid(self):
            return self._obj[0]['type']

        def get_name(self):
            """Get the name of this entry.

            :return: entry name as a python string
            """
            oid = self.get_oid()
            return short_names.get(oid, str(oid))

        def get_code(self):
            """Get the name of this entry.

            :return: entry name as a python string
            """
            oid = self.get_oid()
            return code_names.get(oid, str(oid))

        def get_value(self):
            """Get the value of this entry.

            :return: entry value as a python string
            """
            value = self._obj[0]['value']
            der = value.asOctets()
            oid = self.get_oid()
            if oid not in name_oids:
                return 'UNKNOWN'

            name_spec = name_oids[oid]()

            value = decoder.decode(der, asn1Spec=name_spec)[0]
            if hasattr(value, 'getComponent'):
                value = value.getComponent()
            return value.asOctets().decode(value.encoding)

    def __init__(self, name_obj=None):
        if name_obj is not None:
            if not isinstance(name_obj, rfc2459.RDNSequence):
                raise TypeError("name is not an RDNSequence")
            # TODO(stan): actual copy
            self._name_obj = name_obj
        else:
            self._name_obj = rfc2459.RDNSequence()

    def __str__(self):
        return '/' + '/'.join("%s=%s" % (e.get_code(), e.get_value())
                              for e in self)

    def __len__(self):
        return len(self._name_obj)

    def __getitem__(self, idx):
        return X509Name.Entry(self._name_obj[idx])

    def __iter__(self):
        for i in range(len(self)):
            yield self[i]

    def add_name_entry(self, oid, text):
        if not isinstance(oid, asn1_univ.ObjectIdentifier):
            raise errors.X509Error("oid '%s' is not valid" % (oid,))
        entry = rfc2459.RelativeDistinguishedName()
        entry[0] = rfc2459.AttributeTypeAndValue()
        entry[0]['type'] = oid
        name_type = name_oids[oid]
        try:
            if name_type in (rfc2459.X520countryName, rfc2459.Pkcs9email):
                val = name_type(text)
            else:
                val = name_type()
                val['utf8String'] = text
        except asn1_error.ValueConstraintError:
            raise errors.X509Error("Name '%s' is not valid" % text)
        entry[0]['value'] = rfc2459.AttributeValue(encoder.encode(val))
        self._name_obj[len(self)] = entry

    def get_entries_by_oid(self, oid):
        """Get a name entry corresponding to an NID name.

        :param nid: an NID for the new name entry
        :return: An X509Name.Entry object
        """
        return [entry for entry in self if entry.get_oid() == oid]
