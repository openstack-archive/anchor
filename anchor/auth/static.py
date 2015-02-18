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

from pecan import conf

from .results import AUTH_FAILED
from .results import AuthDetails


def login(user, secret):
    # expected values
    e_user = str(conf.auth['static']['user'])
    e_pass = str(conf.auth['static']['secret'])
    user = str(user)
    secret = str(secret)

    # In python, len(<string>) is O(1)
    # Short circuit this if lengths don't match
    if len(user) != len(e_user):
        return AUTH_FAILED
    if len(secret) != len(e_pass):
        return AUTH_FAILED

    # This technique is used to provide a constant time string compare
    # between the user input and the expected values.
    valid_user = hmac.compare_digest(user, e_user)
    valid_pass = hmac.compare_digest(secret, e_pass)

    # This if statement results in a potential timing attack where the
    # statement could return more quickly if valid_secret=False. We
    # do not see an obvious solution to this problem, but also believe
    # that leaking which input was valid isn't as big of a concern.
    if valid_user and valid_pass:
        return AuthDetails(username=e_user, groups=[])

    return AUTH_FAILED
