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

import base64
import os
import re
import stat

from anchor import errors


# RFC1034 allows a simple " " too, but it's not allowed in certificates, so it
# will not match
RE_DOMAIN_LABEL = re.compile("^[a-z](?:[-a-z0-9]*[a-z0-9])?$", re.IGNORECASE)


def verify_domain(domain, allow_wildcards=False):
    labels = domain.split('.')
    if labels[-1] == "":
        # single trailing . is ok, ignore
        labels.pop(-1)

    for i, label in enumerate(labels):
        if len(label) > 63:
            raise ValueError(
                "domain <%s> it too long (RFC5280/4.2.1.6)" % (domain,))

        # check for wildcard labels, ignore partial-wildcard labels
        if '*' == label and allow_wildcards:
            if i != 0:
                raise ValueError(
                    "domain <%s> has wildcard that's not in the "
                    "left-most label (RFC6125/6.4.3)" % (domain,))
        else:
            if RE_DOMAIN_LABEL.match(label) is None:
                raise ValueError(
                    "domain <%s> contains invalid characters "
                    "(RFC1034/3.5)" % (domain,))


def extract_pem(data, use_markers=True):
    """Extract and unpack PEM data

    Anything between the BEGIN and END lines will be unpacked using base64. The
    specific BEGIN/END content name is ignored since it's not standard anyway.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    lines = data.splitlines()
    seen_start = not use_markers
    b64_content = b""
    for line in lines:
        if line.startswith(b"-----END ") and line.endswith(b"-----"):
            break
        if seen_start:
            b64_content += line
        if line.startswith(b"-----BEGIN ") and line.endswith(b"-----"):
            seen_start = True

    if not b64_content:
        return None
    decoder = getattr(base64, 'decodebytes', base64.decodestring)
    return decoder(b64_content)


def check_file_permissions(path):
    # checks that file is owner readable only
    expected_permissions = (stat.S_IRUSR | stat.S_IFREG)  # 0o100400
    st = os.stat(path)
    if st.st_mode != expected_permissions:
        raise errors.ConfigValidationException("CA file: %s has incorrect "
                                               "permissions set, expected "
                                               "owner readable only" % path)


def check_file_exists(path):
    if not (os.path.isfile(path) and
            os.access(path, os.R_OK)):
        raise errors.ConfigValidationException("could not read file: %s" %
                                               path)
