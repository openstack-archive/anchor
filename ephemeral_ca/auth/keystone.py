from .results import AuthDetails, AUTH_FAILED

import json
import logging
from pecan import conf
import requests

logger = logging.getLogger(__name__)


def login(token):
    data = json.dumps({"auth": {
        "identity": {
            "methods": ["token"],
                "token": {
                    "id": token
                }}}})
    req = requests.post(conf.auth['keystone']['url'] + '/v3/auth/tokens', headers={'Content-Type': 'application/json'}, data=data)
    if not (200 <= req.status_code < 300):
        logger.info("Authentication failed for token <%s>, status %s", token, req.status_code)
        return AUTH_FAILED

    try:
        res = req.json()
        user = res['token']['user']['name']

        roles = [role['name'] for role in res['token']['roles']]
    except Exception as e:
        logger.exception("Keystone response was not in the expected format")
        return AUTH_FAILED

    return AuthDetails(username=user, groups=roles)
