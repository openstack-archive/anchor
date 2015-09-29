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

import hmac
import re


def constant_time_compare(val1, val2):
    """Returns True if the two strings are equal, False otherwise.

       Tries to use the standard library, if available. Otherwise
       falls back to a local implementation.
    """
    try:
        return hmac.compare_digest(val1, val2)
    except AttributeError:
        return _constant_time_compare(val1, val2)


def _constant_time_compare(val1, val2):
    """Returns True if the two strings are equal, False otherwise.

       The time taken is independent of the number of characters that
       match. For the sake of simplicity, this function executes in
       constant time only when the two strings have the same length. It
       short-circuits when they have different lengths.

       This function was derrived from the django crypto utils.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0


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
