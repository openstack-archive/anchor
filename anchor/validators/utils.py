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

from anchor.validators import errors
from anchor.X509 import extension


logger = logging.getLogger(__name__)


def csr_require_cn(csr):
    cns = csr.get_subject_cn()
    if not cns:
        raise errors.ValidationError("CSR is lacking a CN in the Subject")
    if len(cns) > 1:
        raise errors.ValidationError("CSR has too many CN entries")
    return cns[0]


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


def maybe_ip(name):
    try:
        return netaddr.IPAddress(name)
    except ValueError:
        # happens when trying to pass a subnet prefix
        return None
    except netaddr.AddrFormatError:
        return None


def maybe_range(name):
    try:
        return netaddr.IPNetwork(name)
    except netaddr.AddrFormatError:
        return None


def compare_name_pattern(name, pattern, allow_wildcard):
    """Compare domain names including wildcards.

    Wilcard means local Anchor wildcard which is '%'. This allows the pattern
    to match an actual wildcard entry (*) or name which can be expanded.
    Partial matches using % are allowed, but % matches only in one label.

    In practice that means:
    name:                    pattern:              wildard: result:
    example.com              example.com           -        match
    *.example.com            *.example.com         -        match
    *.example.com            %.example.com         true     match
    *.example.com            %.example.com         false    fail
    abc.example.com          %.example.com         -        match
    abc.def.example.com      %.example.com         -        fail
    abc.def.example.com      %.%.example.com       -        match
    host-123.example.com     host-%.example.com    -        match
    """

    name_labels = name.split('.')
    patt_labels = pattern.split('.')
    if len(name_labels) != len(patt_labels):
        return False

    for nl, pl in zip(name_labels, patt_labels):
        if '%' in pl:
            pre, _, post = pl.partition('%')

            if not nl.startswith(pre):
                return False
            nl = nl[len(pre):]  # strip the pre part of pattern

            if not nl.endswith(post):
                return False
            if len(post) > 0:
                nl = nl[:-len(post)]  # strip the post part of pattern

            if '*' in nl and not allow_wildcard:
                return False
        else:
            if nl != pl:
                return False

    return True
