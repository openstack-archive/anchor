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

from anchor import jsonloader

import oslo_config
import oslo_messaging
from pycadf import cadftaxonomy
from pycadf import event
from pycadf import identifier
from pycadf import resource


logger = logging.getLogger(__name__)
target = None
notifier = None


def _emit_event(event_type, payload):
    if not payload.is_valid():
        logger.error("created invalid audit event: %s", payload)
        return

    if notifier is not None:
        notifier.info({}, event_type, payload.as_dict())


def _event_defaults(result):
    # eventType, id, eventTime are filled in automatically by pyCADF
    return {
        'outcome': (cadftaxonomy.OUTCOME_SUCCESS if result else
                    cadftaxonomy.OUTCOME_FAILURE),
        }


def _user_resource(username):
    return resource.Resource(
        # TODO(stan): generate id from username if it's known
        # this should also get username from keystone tokens to work correctly
        id=identifier.generate_uuid(),
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


def _certificate_resource(fingerprint):
    if fingerprint is None:
        res_id = identifier.generate_uuid()
    else:
        res_id = "certificate:%s" % (fingerprint,)
    return resource.Resource(
        id=res_id,
        typeURI=cadftaxonomy.SECURITY_KEY,
        )


def emit_auth_event(ra_name, username, result):
    params = _event_defaults(result)
    params['action'] = 'authenticate'
    params['initiator'] = _user_resource(username)
    auth_res = _auth_resource(ra_name)
    params['observer'] = auth_res
    params['target'] = auth_res
    _emit_event('audit.auth', event.Event(**params))


def emit_signing_event(ra_name, username, result, fingerprint=None):
    params = _event_defaults(result)
    params['action'] = 'evaluate'
    params['initiator'] = _user_resource(username)
    params['observer'] = _policy_resource(ra_name)
    params['target'] = _certificate_resource(fingerprint)
    # add when pycadf merges event names
    # params['name'] = "certificate signing"
    _emit_event('audit.sign', event.Event(**params))


def init_audit():
    global target
    global notifier
    audit_conf = jsonloader.config_for_audit()
    if audit_conf is None:
        return

    target = audit_conf.get('target', 'log')
    cfg = oslo_config.cfg.ConfigOpts()
    if target == 'messaging':
        transport = oslo_messaging.get_transport(cfg, url=audit_conf['url'])
    else:
        transport = oslo_messaging.get_transport(cfg)
    notifier = oslo_messaging.Notifier(transport, 'anchor', driver=target)
