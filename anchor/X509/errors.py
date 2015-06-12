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

# not needed right now, just to be consistent and future-proof
from __future__ import absolute_import


class X509Error(Exception):
    """Base exception for X509 errors."""
    def __init__(self, what):
        super(X509Error, self).__init__(what)


class ASN1TimeError(Exception):
    """Base exception for ASN1-time related errors."""
    pass


class ASN1StringError(X509Error):
    """Base exception for ASN1-string related errors."""
    pass
