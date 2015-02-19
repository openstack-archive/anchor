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
import logging

from pecan import conf

from .results import AuthDetails


logger = logging.getLogger(__name__)


def login(user, secret):
    """Validates a user supplied user/password against an expected value.

       The expected value is pulled from the pecan config. Note that this
       value is currently stored in the clear inside that config, so we
       are assuming that the config is protected using file perms, etc.

       This function provides some resistance to timing attacks, but
       information on the expected user/password lengths can still be
       leaked. It may also be possible to use a timing attack to see
       which input failed validation. See comments below for details.

       :param user: The user supplied username (unicode or string)
       :param secret: The user supplied password (unicode or string)
       :return: None on failure or an AuthDetails object on success
    """
    # convert input to strings
    user = str(user)
    secret = str(secret)

    # expected values
    try:
        e_user = str(conf.auth['static']['user'])
        e_pass = str(conf.auth['static']['secret'])
    except (KeyError, TypeError):
        logger.warn("auth conf missing static user or secret")
        return None

    # In python, len(<string>) is O(1)
    # Short circuit this if lengths don't match
    if len(user) != len(e_user):
        logger.info("failed static auth: invalid username ({})".format(user))
        return None
    if len(secret) != len(e_pass):
        logger.info("failed static auth: invalid password")
        return None

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

    logger.info("failed static auth for user {}".format(user))
