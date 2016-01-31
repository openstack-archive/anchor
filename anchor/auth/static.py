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

import logging

from anchor.auth import results
from anchor import jsonloader

from oslo_utils import secretutils as util

logger = logging.getLogger(__name__)


def login(ra_name, user, secret):
    """Validates a user supplied user/password against an expected value.

       The expected value is pulled from the pecan config. Note that this
       value is currently stored in the clear inside that config, so we
       are assuming that the config is protected using file perms, etc.

       This function provides some resistance to timing attacks, but
       information on the expected user/password lengths can still be
       leaked. It may also be possible to use a timing attack to see
       which input failed validation. See comments below for details.

       :param ra_name: name of the registration authority
       :param user: The user supplied username (unicode or string)
       :param secret: The user supplied password (unicode or string)
       :return: None on failure or an AuthDetails object on success
    """
    auth_conf = jsonloader.authentication_for_registration_authority(ra_name)

    # convert input to strings
    user = str(user)
    secret = str(secret)

    # expected values
    try:
        expected_user = str(auth_conf['user'])
        expected_secret = str(auth_conf['secret'])
    except (KeyError, TypeError):
        logger.warning("auth conf missing static user or secret")
        return None

    # This technique is used to provide a constant time string compare
    # between the user input and the expected values.
    valid_user = util.constant_time_compare(user, expected_user)
    valid_secret = util.constant_time_compare(secret, expected_secret)

    # This if statement results in a potential timing attack where the
    # statement could return more quickly if valid_secret=False. We
    # do not see an obvious solution to this problem, but also believe
    # that leaking which input was valid isn't as big of a concern.
    if valid_user and valid_secret:
        return results.AuthDetails(username=expected_user, groups=[])

    logger.info("failed static auth for user {}".format(user))
