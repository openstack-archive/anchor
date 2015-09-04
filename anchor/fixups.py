# -*- coding:utf-8 -*-
#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
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

import netaddr

from anchor.X509 import extension


def enforce_alternative_names_present(csr=None, **kwargs):
    """Make sure that if CN is set, it's also present in SAN extension."""
    sans = csr.get_extensions(extension.X509ExtensionSubjectAltName)
    if sans:
        san = sans[0]
    else:
        san = extension.X509ExtensionSubjectAltName()

    san_updated = False
    for cn in csr.get_subject_cn():
        try:
            ip = netaddr.IPAddress(cn)
            if ip not in san.get_ips():
                san.add_ip(ip)
                san_updated = True
        except netaddr.AddrFormatError:
            if cn not in san.get_dns_ids():
                san.add_dns_id(cn)
                san_updated = True

    if san_updated:
        csr.add_extension(san)
    return csr
