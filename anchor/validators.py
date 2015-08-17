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

import logging

import netaddr

from anchor.X509 import errors
from anchor.X509 import extension
from anchor.X509 import name as x509_name


logger = logging.getLogger(__name__)


class ValidationError(Exception):
    pass


def csr_get_cn(csr):
    name = csr.get_subject()
    data = name.get_entries_by_oid(x509_name.OID_commonName)
    if len(data) > 0:
        return data[0].get_value()
    else:
        raise ValidationError("CSR is lacking a CN in the Subject")


def check_domains(domain, allowed_domains):
    if allowed_domains:
        if not any(domain.endswith(suffix) for suffix in allowed_domains):
            # no domain matched
            return False
    else:
        # no valid domains were provided, so we can't make any assertions
        logger.warning("No domains were configured for validation. Anchor "
                       "will issue certificates for any domain, this is not a "
                       "recommended configuration for production environments")
    return True


def iter_alternative_names(csr, types, fail_other_types=True):
    for ext in csr.get_extensions():
        if isinstance(ext, extension.X509ExtensionSubjectAltName):
            # TODO(stan): fail on other types
            if 'DNS' in types:
                for dns_id in ext.get_dns_ids():
                    yield ('DNS', dns_id)
            if 'IP Address' in types:
                for ip in ext.get_ips():
                    yield ('IP Address', ip)


def check_networks(ip, allowed_networks):
    """Check the IP is within an allowed network."""
    if not isinstance(ip, netaddr.IPAddress):
        raise TypeError("ip must be a netaddr ip address")

    if not allowed_networks:
        # no valid networks were provided, so we can't make any assertions
        logger.warning("No valid network IP ranges were given, skipping")
        return True

    if any(ip in netaddr.IPNetwork(net) for net in allowed_networks):
        return True

    return False


def common_name(csr, allowed_domains=[], allowed_networks=[], **kwargs):
    """Check the CN entry is a known domain.

    Refuse requests for certificates if they contain multiple CN
    entries, or the domain does not match the list of known suffixes.
    """
    alt_present = any(ext.get_name() == "subjectAltName"
                      for ext in csr.get_extensions())

    CNs = csr.get_subject().get_entries_by_oid(x509_name.OID_commonName)

    if len(CNs) > 1:
        raise ValidationError("Too many CNs in the request")

    # rfc5280#section-4.2.1.6 says so
    if len(CNs) == 0 and not alt_present:
        raise ValidationError("Alt subjects have to exist if the main"
                              " subject doesn't")

    if len(CNs) > 0:
        cn = csr_get_cn(csr)
        try:
            # is it an IP rather than domain?
            ip = netaddr.IPAddress(cn)
            if not (check_networks(ip, allowed_networks)):
                raise ValidationError("Address '%s' not allowed (does not "
                                      "match known networks)" % cn)
        except netaddr.AddrFormatError:
            if not (check_domains(cn, allowed_domains)):
                raise ValidationError("Domain '%s' not allowed (does not "
                                      "match known domains)" % cn)


def alternative_names(csr, allowed_domains=[], **kwargs):
    """Check known domain alternative names.

    Refuse requests for certificates if the domain does not match
    the list of known suffixes, or network ranges.
    """

    for _, name in iter_alternative_names(csr, ['DNS']):
        if not check_domains(name, allowed_domains):
            raise ValidationError("Domain '%s' not allowed (doesn't"
                                  " match known domains)"
                                  % name)


def alternative_names_ip(csr, allowed_domains=[], allowed_networks=[],
                         **kwargs):
    """Check known domain and ip alternative names.

    Refuse requests for certificates if the domain does not match
    the list of known suffixes, or network ranges.
    """

    for name_type, name in iter_alternative_names(csr, ['DNS', 'IP Address']):
        if name_type == 'DNS' and not check_domains(name, allowed_domains):
            raise ValidationError("Domain '%s' not allowed (doesn't"
                                  " match known domains)" % name)
        if name_type == 'IP Address':
            if not check_networks(name, allowed_networks):
                raise ValidationError("IP '%s' not allowed (doesn't"
                                      " match known networks)" % name)


def blacklist_names(csr, domains=[], **kwargs):
    """Check for blacklisted names in CN and altNames."""

    if not domains:
        logger.warning("No domains were configured for the blacklist filter, "
                       "consider disabling the step or providing a list")
        return

    CNs = csr.get_subject().get_entries_by_oid(x509_name.OID_commonName)
    if len(CNs) > 0:
        cn = csr_get_cn(csr)
        if check_domains(cn, domains):
            raise ValidationError("Domain '%s' not allowed "
                                  "(CN blacklisted)" % cn)

    for _, name in iter_alternative_names(csr, ['DNS'],
                                          fail_other_types=False):
        if check_domains(name, domains):
            raise ValidationError("Domain '%s' not allowed "
                                  "(alt blacklisted)" % name)


def server_group(auth_result=None, csr=None, group_prefixes={}, **kwargs):
    """Check Team prefix.

    Make sure that for server names containing a team prefix, the team is
    verified against the groups the user is a member of.
    """

    cn = csr_get_cn(csr)
    parts = cn.split('-')
    if len(parts) == 1 or '.' in parts[0]:
        return  # no prefix

    if parts[0] in group_prefixes:
        if group_prefixes[parts[0]] not in auth_result.groups:
            raise ValidationError("Server prefix doesn't match user groups")


def extensions(csr=None, allowed_extensions=[], **kwargs):
    """Ensure only accepted extensions are used."""
    exts = csr.get_extensions() or []
    for ext in exts:
        if ext.get_name() not in allowed_extensions:
            raise ValidationError("Extension '%s' not allowed"
                                  % ext.get_name())


def key_usage(csr=None, allowed_usage=None, **kwargs):
    """Ensure only accepted key usages are specified."""
    allowed = set(extension.LONG_KEY_USAGE_NAMES.get(x, x) for x in
                  allowed_usage)
    denied = set()

    for ext in (csr.get_extensions() or []):
        if isinstance(ext, extension.X509ExtensionKeyUsage):
            usages = set(ext.get_all_usages())
            denied = denied | (usages - allowed)
    if denied:
        raise ValidationError("Found some not allowed key usages: %s"
                              % ', '.join(denied))


def ca_status(csr=None, ca_requested=False, **kwargs):
    """Ensure the request has/hasn't got the CA flag."""
    request_ca_flags = False
    for ext in (csr.get_extensions() or []):
        if isinstance(ext, extension.X509ExtensionBasicConstraints):
            if ext.get_ca():
                if not ca_requested:
                    raise ValidationError(
                        "CA status requested, but not allowed")
                request_ca_flags = True
        elif isinstance(ext, extension.X509ExtensionKeyUsage):
            has_cert_sign = ext.get_usage('keyCertSign')
            has_crl_sign = ext.get_usage('cRLSign')
            if has_crl_sign or has_cert_sign:
                if not ca_requested:
                    raise ValidationError(
                        "Key usage doesn't match requested CA status "
                        "(keyCertSign/cRLSign: %s/%s)"
                        % (has_cert_sign, has_crl_sign))
                request_ca_flags = True
    if ca_requested and not request_ca_flags:
        raise ValidationError("CA flags required")


def source_cidrs(request=None, cidrs=None, **kwargs):
    """Ensure that the request comes from a known source."""
    for cidr in cidrs:
        try:
            r = netaddr.IPNetwork(cidr)
            if request.client_addr in r:
                return
        except netaddr.AddrFormatError:
            raise ValidationError("Cidr '%s' does not describe a valid"
                                  " network" % cidr)
    raise ValidationError("No network matched the request source '%s'" %
                          request.client_addr)


def csr_signature(csr=None, **kwargs):
    """Ensure that the CSR has a valid self-signature."""
    try:
        if not csr.verify():
            raise ValidationError("Signature on the CSR is not valid")
    except errors.X509Error:
        raise ValidationError("Signature on the CSR is not valid")
