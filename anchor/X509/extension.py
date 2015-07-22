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
from pyasn1.type import univ as asn1_univ
from pyasn1.type import namedtype as asn1_namedtype
from pyasn1.type import constraint as asn1_constraint
from pyasn1.type import tag as asn1_tag
from pyasn1_modules import rfc2459  # X509v3


EXTENSION_NAMES = {
    rfc2459.id_ce_policyConstraints: 'policyConstraints',
    rfc2459.id_ce_basicConstraints: 'basicConstraints',
    rfc2459.id_ce_subjectDirectoryAttributes: 'subjectDirectoryAttributes',
    rfc2459.id_ce_deltaCRLIndicator: 'deltaCRLIndicator',
    rfc2459.id_ce_cRLDistributionPoints: 'cRLDistributionPoints',
    rfc2459.id_ce_issuingDistributionPoint: 'issuingDistributionPoint',
    rfc2459.id_ce_nameConstraints: 'nameConstraints',
    rfc2459.id_ce_certificatePolicies: 'certificatePolicies',
    rfc2459.id_ce_policyMappings: 'policyMappings',
    rfc2459.id_ce_privateKeyUsagePeriod: 'privateKeyUsagePeriod',
    rfc2459.id_ce_keyUsage: 'keyUsage',
    rfc2459.id_ce_authorityKeyIdentifier: 'authorityKeyIdentifier',
    rfc2459.id_ce_subjectKeyIdentifier: 'subjectKeyIdentifier',
    rfc2459.id_ce_certificateIssuer: 'certificateIssuer',
    rfc2459.id_ce_subjectAltName: 'subjectAltName',
    rfc2459.id_ce_issuerAltName: 'issuerAltName',
}


class X509ExtensionValue(object):
    def __init__(self, ext_der=None):
        if ext_der:
            self._ext = decoder.decode(ext_der, self.spec())[0]
        else:
            self._ext = self.spec()

    def get_oid(self):
        return self.oid


class BasicConstraints(asn1_univ.Sequence):
    """Custom BasicConstraint implementation until pyasn1_modules fixes theirs."""
    componentType = asn1_namedtype.NamedTypes(
        asn1_namedtype.DefaultedNamedType('cA', asn1_univ.Boolean(False)),
        asn1_namedtype.OptionalNamedType('pathLenConstraint', asn1_univ.Integer().subtype(subtypeSpec=asn1_constraint.ValueRangeConstraint(0, 64)))
    )


class X509ExtensionBasicConstraints(X509ExtensionValue):
    oid = rfc2459.id_ce_basicConstraints
    spec = BasicConstraints

    def get_ca(self):
        return bool(self._ext['cA'])

    def set_ca(self, ca):
        self._ext['cA'] = ca

    def get_path_len_constraint(self):
        return self._ext['pathLenConstraint']

    def set_path_len_constraint(self, length):
        self._ext['pathLenConstraint'] = length

    def __str__(self):
        return "CA: %s, pathLen: %s" % (str(self.get_ca()).upper(), self.get_path_len_constraint())


class X509ExtensionKeyUsage(X509ExtensionValue):
    oid = rfc2459.id_ce_keyUsage
    spec = rfc2459.KeyUsage

    fields = dict(spec.namedValues.namedValues)
    inv_fields = dict((v, k) for k, v in spec.namedValues.namedValues)

    def get_usage(self, arg):
        pos = self.fields[arg]
        if pos >= len(self._ext):
            return False 
        return bool(self._ext[pos])

    def get_all_usages(self):
        return [self.inv_fields[i] for i, enabled in enumerate(self._ext) if enabled]

    def __str__(self):
        return ', '.join(self.get_all_usages())


EXTENSION_CLASSES = {
    rfc2459.id_ce_basicConstraints: X509ExtensionBasicConstraints,
    rfc2459.id_ce_keyUsage: X509ExtensionKeyUsage,
}


class X509Extension(object):
    """An X509 V3 Certificate extension."""
    def __init__(self, ext):
        if not isinstance(ext, rfc2459.Extension):
            raise errors.X509Error("extension has incorrect type")
        self._ext = ext

    def __str__(self):
        return "%s %s" % (self.get_name(), self.get_value())

    def get_oid(self):
        return self._ext['extnID']

    def get_name(self):
        """Get the extension name as a python string."""
        oid = self.get_oid()
        return EXTENSION_NAMES.get(oid, oid)

    def get_value(self):
        """Get the extension value as a python string."""
        oid = self.get_oid()
        value = decoder.decode(self._ext['extnValue'])[0]
        if oid in EXTENSION_CLASSES:
            return EXTENSION_CLASSES[oid](value)
        else:
            return value
