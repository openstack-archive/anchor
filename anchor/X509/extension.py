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

import functools

import netaddr
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import constraint as asn1_constraint
from pyasn1.type import namedtype as asn1_namedtype
from pyasn1.type import tag as asn1_tag
from pyasn1.type import univ as asn1_univ
from pyasn1_modules import rfc2459  # X509v3

from anchor.X509 import errors
from anchor.X509 import utils


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


LONG_KEY_USAGE_NAMES = {
    "Digital Signature": "digitalSignature",
    "Non Repudiation": "nonRepudiation",
    "Key Encipherment": "keyEncipherment",
    "Data Encipherment": "dataEncipherment",
    "Key Agreement": "keyAgreement",
    "Certificate Sign": "keyCertSign",
    "CRL Sign": "cRLSign",
    "Encipher Only": "encipherOnly",
    "Decipher Only": "decipherOnly",
}


def uses_ext_value(f):
    """Wrapper allowing reading of extension value.

    Because the value is normally saved in a (double) serialised way, it's
    not easily accessible to the member methods. This is made easier by
    unpacking the extension value into an extra argument.
    """
    @functools.wraps(f)
    def ext_value_filled(self, *args, **kwargs):
        kwargs['ext_value'] = self._get_value()
        return f(self, *args, **kwargs)
    return ext_value_filled


def modifies_ext_value(f):
    """Wrapper allowing modification of extension value.

    Because the value is normally saved in a (double) serialised way, it's
    not easily accessible to the member methods. This is made easier by
    unpacking the extension value into an extra argument.
    New value needs to be returned from the method.
    """
    @functools.wraps(f)
    def ext_value_filled(self, *args, **kwargs):
        value = self._get_value()
        kwargs['ext_value'] = value
        # since some elements like NamedValue are pure value types, there is
        # no interface to modify them and new versions have to be returned
        value = f(self, *args, **kwargs)
        self._set_value(value)
    return ext_value_filled


class BasicConstraints(asn1_univ.Sequence):
    """Custom BasicConstraint implementation until pyasn1_modules is fixes."""
    componentType = asn1_namedtype.NamedTypes(
        asn1_namedtype.DefaultedNamedType('cA', asn1_univ.Boolean(False)),
        asn1_namedtype.OptionalNamedType(
            'pathLenConstraint',
            asn1_univ.Integer().subtype(
                subtypeSpec=asn1_constraint.ValueRangeConstraint(0, 64)))
    )


class NameConstraints(asn1_univ.Sequence):
    """Custom NameConstraints implementation until pyasn1_modules is fixed."""
    componentType = asn1_namedtype.NamedTypes(
        asn1_namedtype.OptionalNamedType(
            'permittedSubtrees',
            rfc2459.GeneralSubtrees().subtype(
                implicitTag=asn1_tag.Tag(asn1_tag.tagClassContext,
                                         asn1_tag.tagFormatConstructed, 0))),
        asn1_namedtype.OptionalNamedType(
            'excludedSubtrees',
            rfc2459.GeneralSubtrees().subtype(
                implicitTag=asn1_tag.Tag(asn1_tag.tagClassContext,
                                         asn1_tag.tagFormatConstructed, 1)))
    )


class X509Extension(object):
    """Abstraction for the pyasn1 Extension structures.

    The object should normally be constructed using `construct_extension`,
    which will choose the right extension type based on the id.
    Each extension has an immutable oid and a spec of the internal value
    representation.
    Unknown extension types can be still represented by the
    X509Extension object and copied/serialised without understanding the
    value details. The value will not be displayed properly in the logs
    in the case.
    """
    _oid = None
    spec = None

    """An X509 V3 Certificate extension."""
    def __init__(self, ext=None):
        if ext is None:
            if self.spec is None:
                raise errors.X509Error("cannot create generic extension")
            self._ext = rfc2459.Extension()
            self._ext['extnID'] = self._oid
            self._set_value(self._get_default_value())
        else:
            if not isinstance(ext, rfc2459.Extension):
                raise errors.X509Error("extension has incorrect type")
            self._ext = ext

    @classmethod
    def _get_default_value(cls):
        # if there are any non-optional fields, this needs to be defined in
        # the class
        return cls.spec()

    def __str__(self):
        return "%s: %s" % (self.get_name(), self.get_value_as_str())

    def get_value_as_str(self):
        return "<unknown>"

    def get_oid(self):
        return self._ext['extnID']

    def get_name(self):
        """Get the extension name as a python string."""
        oid = self.get_oid()
        return EXTENSION_NAMES.get(oid, oid)

    def get_critical(self):
        return self._ext['critical']

    def set_critical(self, critical):
        self._ext['critical'] = critical

    def _get_value(self):
        value_der = decoder.decode(self._ext['extnValue'])[0]
        return decoder.decode(value_der, asn1Spec=self.spec())[0]

    def _set_value(self, value):
        if not isinstance(value, self.spec):
            raise errors.X509Error("extension value has incorrect type")
        self._ext['extnValue'] = encoder.encode(rfc2459.univ.OctetString(
            encoder.encode(value)))

    def as_der(self):
        return encoder.encode(self._ext)

    def as_asn1(self):
        return self._ext


class X509ExtensionBasicConstraints(X509Extension):
    spec = BasicConstraints
    _oid = rfc2459.id_ce_basicConstraints

    @uses_ext_value
    def get_ca(self, ext_value=None):
        return bool(ext_value['cA'])

    @modifies_ext_value
    def set_ca(self, ca, ext_value=None):
        ext_value['cA'] = ca
        return ext_value

    @uses_ext_value
    def get_path_len_constraint(self, ext_value=None):
        return ext_value['pathLenConstraint']

    @modifies_ext_value
    def set_path_len_constraint(self, length, ext_value=None):
        ext_value['pathLenConstraint'] = length
        return ext_value

    def __str__(self):
        return "basicConstraints: CA: %s, pathLen: %s" % (
            str(self.get_ca()).upper(), self.get_path_len_constraint())


class X509ExtensionKeyUsage(X509Extension):
    spec = rfc2459.KeyUsage
    _oid = rfc2459.id_ce_keyUsage

    fields = dict(spec.namedValues.namedValues)
    inv_fields = dict((v, k) for k, v in spec.namedValues.namedValues)

    @classmethod
    def _get_default_value(cls):
        # if there are any non-optional fields, this needs to be defined in
        # the class
        return cls.spec("''B")

    @uses_ext_value
    def get_usage(self, usage, ext_value=None):
        usage = LONG_KEY_USAGE_NAMES.get(usage, usage)
        pos = self.fields[usage]
        if pos >= len(ext_value):
            return False
        return bool(ext_value[pos])

    @uses_ext_value
    def get_all_usages(self, ext_value=None):
        return [self.inv_fields[i] for i, enabled in enumerate(ext_value)
                if enabled]

    @modifies_ext_value
    def set_usage(self, usage, state, ext_value=None):
        usage = LONG_KEY_USAGE_NAMES.get(usage, usage)
        pos = self.fields[usage]
        values = [x for x in ext_value]

        if state:
            while pos >= len(values):
                values.append(0)
            values[pos] = 1
        else:
            if pos < len(values):
                values[pos] = 0

        bits = ''.join(str(x) for x in values)
        return self.spec("'%s'B" % bits)

    def __str__(self):
        return "keyUsage: " + ", ".join(self.get_all_usages())


class X509ExtensionSubjectAltName(X509Extension):
    spec = rfc2459.SubjectAltName
    _oid = rfc2459.id_ce_subjectAltName

    @uses_ext_value
    def get_dns_ids(self, ext_value=None):
        dns_ids = []
        for name in ext_value:
            if name.getName() != 'dNSName':
                continue
            component = name.getComponent()
            dns_id = component.asOctets().decode(component.encoding)
            dns_ids.append(dns_id)
        return dns_ids

    @uses_ext_value
    def get_ips(self, ext_value=None):
        ips = []
        for name in ext_value:
            if name.getName() != 'iPAddress':
                continue
            ips.append(utils.asn1_to_netaddr(name.getComponent()))
        return ips

    @modifies_ext_value
    def add_dns_id(self, dns_id, ext_value=None):
        # TODO(stan) validate dns_id
        new_pos = len(ext_value)
        ext_value[new_pos] = None
        ext_value[new_pos]['dNSName'] = dns_id
        return ext_value

    @modifies_ext_value
    def add_ip(self, ip, ext_value=None):
        if not isinstance(ip, netaddr.IPAddress):
            raise errors.X509Error("not a real ip address provided")
        new_pos = len(ext_value)
        ext_value[new_pos] = None
        ext_value[new_pos]['iPAddress'] = utils.netaddr_to_asn1(ip)
        return ext_value

    @uses_ext_value
    def __str__(self, ext_value=None):
        entries = ["DNS:%s" % (x,) for x in self.get_dns_ids()]
        entries += ["IP:%s" % (x,) for x in self.get_ips()]
        return "subjectAltName: " + ", ".join(entries)


class X509ExtensionNameConstraints(X509Extension):
    spec = NameConstraints
    _oid = rfc2459.id_ce_nameConstraints

    def _get_permitted(self, ext_value):
        return ext_value['permittedSubtrees'] or []

    def _get_excluded(self, ext_value):
        return ext_value['excludedSubtrees'] or []

    @uses_ext_value
    def get_permitted_length(self, ext_value=None):
        return len(self._get_permitted(ext_value))

    @uses_ext_value
    def get_permitted_name(self, n, ext_value=None):
        return [(x.getName(), x.getComponent()) for x
                in self._get_permitted(ext_value)[n]['base']]

    @uses_ext_value
    def get_permitted_range(self, n, ext_value=None):
        entry = self._get_permitted(ext_value)[n]
        return (entry['minimum'], entry['maximum'])

    @uses_ext_value
    def get_excluded_length(self, ext_value=None):
        return len(self._get_excluded(ext_value))

    @uses_ext_value
    def get_excluded_name(self, n, ext_value=None):
        return [(x.getName(), x.getComponent()) for x
                in self._get_excluded(ext_value)[n]['base']]

    @uses_ext_value
    def get_excluded_range(self, n, ext_value=None):
        entry = self._get_excluded(ext_value)[n]
        return (entry['minimum'], entry['maximum'])

    def _add_to_tree(self, ext_value, tree_name, position, name_type, name):
        if ext_value[tree_name] is None:
            ext_value[tree_name] = None
        ext_value[tree_name][position] = None
        ext_value[tree_name][position]['base'] = None
        ext_value[tree_name][position]['base'][name_type] = name
        ext_value[tree_name][position]['minimum'] = 0
        # maximum should be missing (RFC5280/4.2.1.10)

    @modifies_ext_value
    def add_permitted(self, name_type, name, ext_value=None):
        last = self.get_permitted_length()
        self._add_to_tree(ext_value, 'permittedSubtrees', last,
                          name_type, name)
        return ext_value

    @modifies_ext_value
    def add_excluded(self, name_type, name, ext_value=None):
        last = self.get_excluded_length()
        self._add_to_tree(ext_value, 'excludedSubtrees', last, name_type, name)
        return ext_value


EXTENSION_CLASSES = {
    rfc2459.id_ce_basicConstraints: X509ExtensionBasicConstraints,
    rfc2459.id_ce_keyUsage: X509ExtensionKeyUsage,
    rfc2459.id_ce_subjectAltName: X509ExtensionSubjectAltName,
    rfc2459.id_ce_nameConstraints: X509ExtensionNameConstraints,
}


def construct_extension(ext):
    """Construct an extension object of the right type.

    While X509Extension can provide basic access to the extension elements,
    it cannot parse details of extensions. This function detects which type
    should be used based on the extension id.
    If the type is unknown, generic X509Extension is used instead.
    """
    if not isinstance(ext, rfc2459.Extension):
        raise errors.X509Error("extension has incorrect type")
    ext_class = EXTENSION_CLASSES.get(ext['extnID'], X509Extension)
    return ext_class(ext)
