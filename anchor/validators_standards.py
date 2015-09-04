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

"""
Standards based validator.

This module provides validators which should be included in all deployments and
which are based directly on the standards documents. All exceptions must have a
comment referencing the document / section they're based on.

All the rules are pulled into a single validator: ``standards_compliance``.
"""

from __future__ import absolute_import

import re

import netaddr

from anchor import validators
from anchor.X509 import errors
from anchor.X509 import extension


def standards_compliance(csr=None, **kwargs):
    """Collection of separate cases of standards validation."""
    _no_extension_duplicates(csr)
    _critical_flags(csr)
    _valid_domains(csr)
    # TODO(stan): validate srv/uri, distinct DNs, email format, identity keys


def _no_extension_duplicates(csr):
    """Only one extension with a given oid is allowed.

    See RFC5280 section 4.2
    """
    seen_oids = set()
    for ext in csr.get_extensions():
        oid = ext.get_oid()
        if oid in seen_oids:
            raise validators.ValidationError(
                "Duplicate extension with oid %s" % oid)
        seen_oids.add(oid)


def _critical_flags(csr):
    """Various rules define whether critical flag is required."""
    for ext in csr.get_extensions():
        if isinstance(ext, extension.X509ExtensionSubjectAltName):
            # RFC5280 section 4.1.2.6
            if len(csr.get_subject()) == 0 and not ext.get_critical():
                raise validators.ValidationError(
                    "SAN must be critical if subject is empty")
        if isinstance(ext, extension.X509ExtensionBasicConstraints):
            # RFC5280 section 4.1.2.9
            if not ext.get_critical():
                raise validators.ValidationError(
                    "Basic constraints has to be marked critical")


# RFC1034 allows a simple " " too, but it's not allowed in certificates, so it
# will not match
RE_DOMAIN_LABEL = re.compile("^[a-z](?:[-a-z0-9]*[a-z0-9])?$", re.IGNORECASE)


def _valid_domains(csr):
    """Format of the domin names

    See RFC5280 section 4.2.1.6
    """
    def check_domains(hostname):
        # See RFC1034 section 3.5
        labels = hostname.split('.')
        if labels[-1] == "":
            # single trailing . is ok, ignore
            labels.pop(-1)
        for label in labels:
            if len(label) > 63:
                return False
            if RE_DOMAIN_LABEL.match(label) is None:
                return False
        return True

    sans = csr.get_extensions(extension.X509ExtensionSubjectAltName)
    if not sans:
        return
    ext = sans[0]
    for domain in ext.get_dns_ids():
        if not check_domains(domain):
            raise validators.ValidationError(
                "SAN entry <%s> is not a valid domain" % (domain,))
