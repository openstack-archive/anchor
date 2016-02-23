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
from pyasn1.type import univ as pyasn1_univ
from pyasn1_modules import rfc2437  # PKCS#1
from pyasn1_modules import rfc2459

from anchor.validators import errors as v_errors
from anchor.validators import utils
from anchor.X509 import extension
from anchor.X509 import name as x509_name


logger = logging.getLogger(__name__)


def common_name(csr, allowed_domains=[], allowed_networks=[], **kwargs):
    """Check the CN entry is a known domain.

    Refuse requests for certificates if they contain multiple CN
    entries, or the domain does not match the list of known suffixes.
    """
    alt_present = any(ext.get_name() == "subjectAltName"
                      for ext in csr.get_extensions())

    CNs = csr.get_subject().get_entries_by_oid(x509_name.OID_commonName)

    if len(CNs) > 1:
        raise v_errors.ValidationError("Too many CNs in the request")

    # rfc2459#section-4.2.1.6 says so
    if len(CNs) == 0 and not alt_present:
        raise v_errors.ValidationError("Alt subjects have to exist if the main"
                                       " subject doesn't")

    if len(CNs) > 0:
        cn = utils.csr_require_cn(csr)
        try:
            # is it an IP rather than domain?
            ip = netaddr.IPAddress(cn)
            if not (utils.check_networks(ip, allowed_networks)):
                raise v_errors.ValidationError(
                    "Address '%s' not allowed (does not match known networks)"
                    % cn)
        except netaddr.AddrFormatError:
            if not (utils.check_domains(cn, allowed_domains)):
                raise v_errors.ValidationError(
                    "Domain '%s' not allowed (does not match known domains)"
                    % cn)


def alternative_names(csr, allowed_domains=[], **kwargs):
    """Check known domain alternative names.

    Refuse requests for certificates if the domain does not match
    the list of known suffixes, or network ranges.
    """

    for _, name in utils.iter_alternative_names(csr, ['DNS']):
        if not utils.check_domains(name, allowed_domains):
            raise v_errors.ValidationError("Domain '%s' not allowed (doesn't"
                                           " match known domains)" % name)


def alternative_names_ip(csr, allowed_domains=[], allowed_networks=[],
                         **kwargs):
    """Check known domain and ip alternative names.

    Refuse requests for certificates if the domain does not match
    the list of known suffixes, or network ranges.
    """

    for name_type, name in utils.iter_alternative_names(csr,
                                                        ['DNS', 'IP Address']):
        if name_type == 'DNS' and not utils.check_domains(name,
                                                          allowed_domains):
            raise v_errors.ValidationError("Domain '%s' not allowed (doesn't"
                                           " match known domains)" % name)
        if name_type == 'IP Address':
            if not utils.check_networks(name, allowed_networks):
                raise v_errors.ValidationError("IP '%s' not allowed (doesn't"
                                               " match known networks)" % name)


def blacklist_names(csr, domains=[], **kwargs):
    """Check for blacklisted names in CN and altNames."""

    if not domains:
        logger.warning("No domains were configured for the blacklist filter, "
                       "consider disabling the step or providing a list")
        return

    CNs = csr.get_subject().get_entries_by_oid(x509_name.OID_commonName)
    if len(CNs) > 0:
        cn = utils.csr_require_cn(csr)
        if utils.check_domains(cn, domains):
            raise v_errors.ValidationError("Domain '%s' not allowed "
                                           "(CN blacklisted)" % cn)

    for _, name in utils.iter_alternative_names(csr, ['DNS'],
                                                fail_other_types=False):
        if utils.check_domains(name, domains):
            raise v_errors.ValidationError("Domain '%s' not allowed "
                                           "(alt blacklisted)" % name)


def server_group(auth_result=None, csr=None, group_prefixes={}, **kwargs):
    """Check Team prefix.

    Make sure that for server names containing a team prefix, the team is
    verified against the groups the user is a member of.
    """

    cn = utils.csr_require_cn(csr)
    parts = cn.split('-')
    if len(parts) == 1 or '.' in parts[0]:
        return  # no prefix

    if parts[0] in group_prefixes:
        if group_prefixes[parts[0]] not in auth_result.groups:
            raise v_errors.ValidationError(
                "Server prefix doesn't match user groups")


def extensions(csr=None, allowed_extensions=[], **kwargs):
    """Ensure only accepted extensions are used."""
    exts = csr.get_extensions() or []
    for ext in exts:
        if (ext.get_name() not in allowed_extensions and
                str(ext.get_oid()) not in allowed_extensions):
            raise v_errors.ValidationError("Extension '%s' not allowed"
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
        raise v_errors.ValidationError("Found some prohibited key usages: %s"
                                       % ', '.join(denied))


def ext_key_usage(csr=None, allowed_usage=None, **kwargs):
    """Ensure only accepted extended key usages are specified."""

    # transform all possible names into oids we actually check
    for i, usage in enumerate(allowed_usage):
        if usage in extension.EXT_KEY_USAGE_NAMES_INV:
            allowed_usage[i] = extension.EXT_KEY_USAGE_NAMES_INV[usage]
        elif usage in extension.EXT_KEY_USAGE_SHORT_NAMES_INV:
            allowed_usage[i] = extension.EXT_KEY_USAGE_SHORT_NAMES_INV[usage]
        else:
            try:
                oid = pyasn1_univ.ObjectIdentifier(usage)
                allowed_usage[i] = oid
            except Exception:
                raise v_errors.ValidationError("Unknown usage: %s" % (usage,))

    allowed = set(allowed_usage)
    denied = set()

    for ext in csr.get_extensions(extension.X509ExtensionExtendedKeyUsage):
        usages = set(ext.get_all_usages())
        denied = denied | (usages - allowed)
    if denied:
        text_denied = [extension.EXT_KEY_USAGE_SHORT_NAMES.get(x)
                       for x in denied]
        raise v_errors.ValidationError("Found some prohibited key usages: %s"
                                       % ', '.join(text_denied))


def source_cidrs(request=None, cidrs=None, **kwargs):
    """Ensure that the request comes from a known source."""
    for cidr in cidrs:
        try:
            r = netaddr.IPNetwork(cidr)
            if request.client_addr in r:
                return
        except netaddr.AddrFormatError:
            raise v_errors.ValidationError(
                "Cidr '%s' does not describe a valid network" % cidr)
    raise v_errors.ValidationError(
        "No network matched the request source '%s'" %
        request.client_addr)


def public_key(csr=None, allowed_keys=None, **kwargs):
    """Ensure the public key has the known type and size.

    Configuration provides a dictionary of key types and minimum sizes.
    """
    if allowed_keys is None or not isinstance(allowed_keys, dict):
        raise v_errors.ValidationError("Allowed keys configuration missing")

    algo = csr.get_public_key_algo()
    algo_names = {
        rfc2437.rsaEncryption: 'RSA',
        rfc2459.id_dsa: 'DSA',
        }
    algo_name = algo_names.get(algo)
    if algo_name is None:
        raise v_errors.ValidationError("Unknown public key type")

    min_size = allowed_keys.get(algo_name)
    if min_size is None:
        raise v_errors.ValidationError(
            "Key type not allowed (%s)" % (algo_name,))
    if min_size == 0:
        # key size is not enforced
        return

    if csr.get_public_key_size() < min_size:
        raise v_errors.ValidationError("Key size too small")


def _split_names_by_type(names):
    """Identify ips and network ranges in a list of strings."""
    allowed_domains = []
    allowed_ips = []
    allowed_ranges = []
    for name in names:
        ip = utils.maybe_ip(name)
        if ip:
            allowed_ips.append(ip)
            continue
        net = utils.maybe_range(name)
        if net:
            allowed_ranges.append(net)
            continue
        allowed_domains.append(name)

    return (allowed_domains, allowed_ips, allowed_ranges)


def whitelist_names(csr=None, names=[], allow_cn_id=False, allow_dns_id=False,
                    allow_ip_id=False, allow_wildcard=False, **kwargs):
    """Ensure names match the whitelist in the allowed name slots."""

    allowed_domains, allowed_ips, allowed_ranges = _split_names_by_type(names)

    for dns_id in csr.get_subject_dns_ids():
        if not allow_dns_id:
            raise v_errors.ValidationError("IP-ID not allowed")
        valid = False
        for allowed_domain in allowed_domains:
            if utils.compare_name_pattern(dns_id, allowed_domain,
                                          allow_wildcard):
                valid = True
                break
        if not valid:
            raise v_errors.ValidationError(
                "Value `%s` not allowed in DNS-ID" % (dns_id,))

    for ip_id in csr.get_subject_ip_ids():
        if not allow_ip_id:
            raise v_errors.ValidationError("IP-ID not allowed")
        if ip_id in allowed_ips:
            continue
        for net in allowed_ranges:
            if ip_id in net:
                continue
        raise v_errors.ValidationError(
            "Value `%s` not allowed in IP-ID" % (ip_id,))

    for cn_id in csr.get_subject_cn():
        if not allow_cn_id:
            raise v_errors.ValidationError("CN-ID not allowed")
        ip = utils.maybe_ip(cn_id)
        if ip:
            # current CN is an ip address
            if ip in allowed_ips:
                continue
            if any((ip in net) for net in allowed_ranges):
                continue
            raise v_errors.ValidationError(
                "Value `%s` not allowed in CN-ID" % (cn_id,))
        else:
            # current CN is a domain
            valid = False
            for allowed_domain in allowed_domains:
                if utils.compare_name_pattern(cn_id, allowed_domain,
                                              allow_wildcard):
                    valid = True
                    break
            if valid:
                continue
            raise v_errors.ValidationError(
                "Value `%s` not allowed in CN-ID" % (cn_id,))

    if csr.has_unknown_san_entries():
        raise v_errors.ValidationError("Request contains unknown SAN entries")
