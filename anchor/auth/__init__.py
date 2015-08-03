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

import pecan

from anchor.auth import keystone  # noqa
from anchor.auth import ldap  # noqa
from anchor.auth import static  # noqa
from anchor import jsonloader


def validate(ra_name, user, secret):
    """Top-level authN entry point.

       This will return an AuthDetails object or abort. This will only
       check that a single auth method. That method will either succeed
       or fail.

       :param ra_name: name of the registration authority
       :param user: user provided user name
       :param secret: user provided secret (password or token)
       :return: AuthDetails if authenticated or aborts
    """
    auth_conf = jsonloader.authentication_for_registration_authority(ra_name)
    backend_name = auth_conf['backend']
    backend = jsonloader.conf.get_authentication(backend_name)
    res = backend(ra_name, user, secret)
    if res:
        return res

    # we should only get here if a module failed to abort
    pecan.abort(401, "authentication failure")
