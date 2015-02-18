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

import hmac

from .results import AUTH_FAILED
from .results import AuthDetails

from pecan import conf

try:
    if conf.auth.get('ldap'):
        from . import ldap
except AttributeError:
    pass  # config not loaded

try:
    if conf.auth.get('keystone'):
        from . import keystone
except AttributeError:
    pass  # config not loaded


def validate(user, secret):
    if conf.auth.get('static'):
        valid_secret = hmac.compare_digest(secret,
                                           conf.auth['static']['secret'])
        valid_user = hmac.compare_digest(user,
                                         conf.auth['static']['user'])
        if valid_secret and valid_user:
            return AuthDetails(username=conf.auth['static']['user'], groups=[])

    if conf.auth.get('ldap'):
        res = ldap.login(user, secret)
        if res is not AUTH_FAILED:
            return res

    if conf.auth.get('keystone'):
        res = keystone.login(secret)
        if res is not AUTH_FAILED:
            return res

    return AUTH_FAILED
