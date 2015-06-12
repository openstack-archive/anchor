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

import json
import logging

import requests

from anchor.auth import results
from anchor import jsonloader


logger = logging.getLogger(__name__)


def login(_, token):
    """Authenticate with the keystone endpoint from configuration file

    :param token: A Keystone Token
    :returns: AuthDetails -- Class used for authentication information
    """
    data = json.dumps({"auth": {
        "identity": {
            "methods": ["token"],
            "token": {
                "id": token
            }}}})
    req = requests.post(jsonloader.conf.auth['keystone']['url'] +
                        '/v3/auth/tokens',
                        headers={'Content-Type': 'application/json'},
                        data=data)
    if req.status_code != 200:
        logger.info("Authentication failed for token <%s>, status %s",
                    token, req.status_code)
        return None

    try:
        res = req.json()
        user = res['token']['user']['name']

        roles = [role['name'] for role in res['token']['roles']]
    except Exception:
        logger.exception("Keystone response was not in the expected format")
        return None

    return results.AuthDetails(username=user, groups=roles)
