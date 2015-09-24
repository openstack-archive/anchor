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

import logging

from pycadf import cadftaxonomy
from pycadf import cadftype
from pycadf import event
from pycadf import identifier
from pycadf import resource
from pycadf import timestamp


logger = logging.getLogger(__name__)


def _emit_event(ev):
    # no actual implementation yet
    if not ev.is_valid():
        logger.error("created invalid audit event: %s", ev)


def _event_defaults(result):
    return {
        'eventType': cadftype.EVENTTYPE_ACTIVITY,
        'id': identifier.generate_uuid(),
        'eventTime': timestamp.get_utc_now(),
        'outcome': (cadftaxonomy.OUTCOME_SUCCESS if result else
                    cadftaxonomy.OUTCOME_FAILURE),
        }


def _user_resource(username):
    return resource.Resource(
        id=identifier.generate_uuid(),  # we don't have stable mapping to user
        typeURI=cadftaxonomy.ACCOUNT_USER,
        name=username)


def _auth_resource(ra_name):
    return resource.Resource(
        id='anchor://authentication',
        typeURI=cadftaxonomy.SERVICE_SECURITY,
        domain=ra_name)


def _policy_resource(ra_name):
    return resource.Resource(
        id='anchor://certificates/policy',
        typeURI=cadftaxonomy.SECURITY_POLICY,
        domain=ra_name)


def emit_auth_event(ra_name, username, result):
    params = _event_defaults(result)
    params['action'] = 'authenticate'
    params['initiator'] = _user_resource(username)
    auth_res = _auth_resource(ra_name)
    params['observer'] = auth_res
    params['target'] = auth_res
    _emit_event(event.Event(**params))


def emit_signing_event(ra_name, username, result):
    params = _event_defaults(result)
    params['action'] = 'evaluate'
    params['initiator'] = _user_resource(username)
    params['observer'] = _policy_resource(ra_name)
    params['target'] = resource.Resource(typeURI=cadftaxonomy.SECURITY_KEY)
    # add when pycadf merges event names
    # params['name'] = "certificate signing"
    _emit_event(event.Event(**params))
