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

"""Anchor internally used validators. They should not be exposed to the
users.
"""

from anchor.validators import errors as v_errors
from anchor.X509 import extension


def ca_status(csr=None, **kwargs):
    """Ensure the request hasn't got the CA or cert signing flag.

    This validation applies both to the BasicConstraints extension and to the
    KeyUsage extension.
    """
    basic_constraint = csr.get_extensions(
        extension.X509ExtensionBasicConstraints)
    if basic_constraint:
        if basic_constraint[0].get_ca():
            raise v_errors.ValidationError(
                "Request is for a CA certificate")

    key_usage = csr.get_extensions(extension.X509ExtensionKeyUsage)
    if key_usage:
        if key_usage[0].get_usage('keyCertSign'):
            raise v_errors.ValidationError(
                "Request contains certificates signing usage flag")
        if key_usage[0].get_usage('cRLSign'):
            raise v_errors.ValidationError(
                "Request contains CRL signing usage flag")
