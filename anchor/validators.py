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

import logging
import socket

import netaddr


logger = logging.getLogger(__name__)


class ValidationError(Exception):
    pass


def csr_get_cn(csr):
    name = csr.get_subject()
    data = name.get_entries_by_nid_name('CN')
    return data[0].get_value()


def check_domains(domain, allowed_domains):
    if not any(domain.endswith(suffix) for suffix in allowed_domains):
        # no domain matched
        return False
    return True


def check_networks(domain, allowed_networks):
    """Check the domain resolves to an IP that is within an allowed network

    Resolve all of the IP addresses for 'domain' and ensure that
    at least one of the IP addresses is listed in allowed_networks for the
    deployment.
    """
    try:
        networks = socket.gethostbyname_ex(domain)
    except socket.gaierror:
        # the domain is not a valid ip address
        return False

    for possible_network in networks[2]:
        ip = netaddr.IPAddress(possible_network)
        if any(ip in netaddr.IPNetwork(net) for net in allowed_networks):
            return True

    return False


def check_networks_strict(domain, allowed_networks):
    """Check the domain resolves to an IP that is within an allowed network

    Resolve all of the IP addresses for 'domain' and ensure that
    at each of the IP addresses is listed in allowed_networks for the
    deployment. This is the stricter form of check_networks.
    """
    try:
        networks = socket.gethostbyname_ex(domain)[2]
    except socket.gaierror:
        # the domain is not a valid ip address
        return False

    for possible_network in networks:
        ip = netaddr.IPAddress(possible_network)
        if not any(ip in netaddr.IPNetwork(net) for net in allowed_networks):
            return False

    return True


def common_name(csr=None, allowed_domains=[], allowed_networks=[], **kwargs):
    """Check CN entire is a known domain.

    Refuse requests for certificates if they contain multiple CN
    entries, or the domain does not match the list of known suffixes
    or network ranges.
    """

    alt_present = any(ext.get_name() == "subjectAltName"
                      for ext in csr.get_extensions())

    CNs = csr.get_subject().get_entries_by_nid_name('CN')

    if alt_present:
        if len(CNs) > 1:
            raise ValidationError("Too many CNs in the request")
    else:
        # rfc5280#section-4.2.1.6 says so
        if len(csr.get_subject()) == 0:
            raise ValidationError("Alt subjects have to exist if the main"
                                  " subject doesn't")

    if len(CNs) > 0:
        cn = csr_get_cn(csr)
        if not (check_domains(cn, allowed_domains) and
                check_networks(cn, allowed_networks)):
            raise ValidationError("Domain '%s' not allowed (doesn't match"
                                  " known domains or networks)" % cn)


def alternative_names(csr=None, allowed_domains=[], **kwargs):
    """Check known domain alternative names.

    Refuse requests for certificates if the domain does not match
    the list of known suffixes, or network ranges.
    """

    for ext in (csr.get_extensions() or []):
        if ext.get_name() == "subjectAltName":
            alternatives = [alt.strip() for alt in ext.get_value().split(',')]
            for alternative in alternatives:
                parts = alternative.split(':', 1)
                if len(parts) != 2 or parts[0] != 'DNS':
                    raise ValidationError("Alt name '%s' does not have a "
                                          "known type" % parts[0])
                if not check_domains(parts[1], allowed_domains):
                    raise ValidationError("Domain '%s' not allowed (doesn't"
                                          " match known domains or networks)"
                                          % parts[1])


def alternative_names_ip(csr=None, allowed_domains=[], allowed_networks=[],
                         **kwargs):
    """Check known domain and ip alternative names.

    Refuse requests for certificates if the domain does not match
    the list of known suffixes, or network ranges.
    """

    for ext in (csr.get_extensions() or []):
        if ext.get_name() == "subjectAltName":
            alternatives = [alt.strip() for alt in ext.get_value().split(',')]
            for alternative in alternatives:
                parts = alternative.split(':', 1)
                if len(parts) != 2 or (parts[0] != 'DNS' and
                                       parts[0] != 'IP Address'):
                    raise ValidationError("Alt name '%s' does not have a "
                                          "known type" % parts[0])
                if not (check_domains(parts[1], allowed_domains) or
                   check_networks(parts[1], allowed_networks)):
                    raise ValidationError("Domain '%s' not allowed (doesn't"
                                          " match known domains or networks)"
                                          % parts[1])


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
    allowed = set(allowed_usage)

    for ext in (csr.get_extensions() or []):
        if ext.get_name() == 'keyUsage':
            usages = set(usage.strip() for usage in ext.get_value().split(','))
            if usages & allowed != usages:
                raise ValidationError("Found some not allowed key usages: %s"
                                      % (usages - allowed))


def ca_status(csr=None, ca_requested=False, **kwargs):
    """Ensure the request has/hasn't got the CA flag."""

    for ext in (csr.get_extensions() or []):
        ext_name = ext.get_name()
        if ext_name == 'basicConstraints':
            options = [opt.strip() for opt in ext.get_value().split(",")]
            for option in options:
                parts = option.split(":")
                if len(parts) != 2:
                    raise ValidationError("Invalid basic constraints flag")

                if parts[0] == 'CA':
                    if parts[1] != str(ca_requested).upper():
                        raise ValidationError("Invalid CA status, 'CA:%s'"
                                              " requested" % parts[1])
                elif parts[0] == 'pathlen':
                    # errr.. it's ok, I guess
                    pass
                else:
                    raise ValidationError("Invalid basic constraints option")
        elif ext_name == 'keyUsage':
            usages = set(usage.strip() for usage in ext.get_value().split(','))
            has_cert_sign = ('Certificate Sign' in usages)
            has_crl_sign = ('CRL Sign' in usages)
            if ca_requested != has_cert_sign or ca_requested != has_crl_sign:
                raise ValidationError("Key usage doesn't match requested CA"
                                      " status (keyCertSign/cRLSign: %s/%s)"
                                      % (has_cert_sign, has_crl_sign))


def source_cidrs(request=None, cidrs=None, **kwargs):
    """Ensure that the request comes from a known source."""
    for cidr in cidrs:
        try:
            r = netaddr.IPNetwork(cidr)
            if request.client_addr in r:
                return
        except netaddr.AddrFormatError:
            raise ValidationError("Cidr <%s> does not describe a valid"
                                  " network", cidr)
    raise ValidationError("No network matched the request source <%s>",
                          request.client_addr)
