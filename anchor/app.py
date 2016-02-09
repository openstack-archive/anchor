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
import os
import sys

import paste
from paste import translogger  # noqa
import pecan

from anchor import audit
from anchor import errors
from anchor import jsonloader

logger = logging.getLogger(__name__)


def config_check_domains(validator_set):
    for name, step in validator_set.items():
        if 'allowed_domains' in step:
            for domain in step['allowed_domains']:
                if not domain.startswith('.'):
                    raise errors.ConfigValidationException(
                        "Domain that does not start with "
                        "a '.' <{}>".format(domain))


def validate_config(conf):
    for old_name in ['auth', 'ca', 'validators']:
        if old_name in conf.config:
            raise errors.ConfigValidationException(
                "The config seems to be for an old version of Anchor. Please "
                "check documentation.")

    if not conf.config.get('registration_authority'):
        raise errors.ConfigValidationException(
            "No registration authorities present")

    if not conf.config.get('signing_ca'):
        raise errors.ConfigValidationException(
            "No signing CA configurations present")

    if not conf.config.get('authentication'):
        raise errors.ConfigValidationException(
            "No authentication methods present")

    for name in conf.registration_authority.keys():
        logger.info("Checking config for registration authority: %s", name)
        validate_registration_authority_config(name, conf)

    for name in conf.signing_ca.keys():
        logger.info("Checking config for signing ca: %s", name)
        validate_signing_ca_config(name, conf)

    for name in conf.authentication.keys():
        logger.info("Checking config for authentication method: %s", name)
        validate_authentication_config(name, conf)

    validate_audit_config(conf)


def validate_audit_config(conf):
    valid_targets = ('messaging', 'log')

    if not conf.config.get('audit'):
        # no audit configuration - that's ok
        return

    audit_conf = conf.audit
    if audit_conf.get('target', 'log') not in valid_targets:
        raise errors.ConfigValidationException(
            "Audit target not known (expected one of %s)" % (
                ", ".join(valid_targets),))

    if audit_conf.get('target') == 'messaging':
        if audit_conf.get('url') is None:
            raise errors.ConfigValidationException("Audit url required")


def validate_authentication_config(name, conf):
    auth_conf = conf.authentication[name]

    default_user = "myusername"
    default_secret = "simplepassword"

    if not auth_conf.get('backend'):
        raise errors.ConfigValidationException(
            "Authentication method %s doesn't define backend" % name)

    if auth_conf['backend'] not in ('static', 'keystone', 'ldap'):
        raise errors.ConfigValidationException(
            "Authentication backend % unknown" % (auth_conf['backend'],))

    # Check for anchor being run with default user/secret
    if auth_conf['backend'] == 'static':
        if auth_conf['user'] == default_user:
            logger.warning("default user for static auth in use")
        if auth_conf['secret'] == default_secret:
            logger.warning("default secret for static auth in use")


def validate_signing_ca_config(name, conf):
    ca_conf = conf.signing_ca[name]
    backend_name = ca_conf.get('backend')
    if not backend_name:
        raise errors.ConfigValidationException(
            "Backend type not defined for RA '%s'" % name)
    sign_func = jsonloader.conf.get_signing_backend(backend_name)
    if not sign_func:
        raise errors.ConfigValidationException(
            "Backend '%s' could not be found" % backend_name)

    if hasattr(sign_func, "_config_validator"):
        sign_func._config_validator(name, ca_conf)


def validate_registration_authority_config(ra_name, conf):
    ra_conf = conf.registration_authority[ra_name]
    auth_name = ra_conf.get('authentication')
    if not auth_name:
        raise errors.ConfigValidationException(
            "No authentication configured for registration authority: %s" %
            ra_name)

    if not conf.authentication.get(auth_name):
        raise errors.ConfigValidationException(
            "Authentication method %s configured for registration authority "
            "%s doesn't exist" % (auth_name, ra_name))

    ca_name = ra_conf.get('signing_ca')
    if not ca_name:
        raise errors.ConfigValidationException(
            "No signing CA configuration present for registration authority: "
            "%s" % ra_name)

    if not conf.signing_ca.get(ca_name):
        raise errors.ConfigValidationException(
            "Signing CA %s configured for registration authority %s doesn't "
            "exist" % (ca_name, ra_name))

    if not ra_conf.get("validators"):
        raise errors.ConfigValidationException(
            "No validators configured for registration authority: %s" %
            ra_name)

    ra_validators = ra_conf['validators']

    for step in ra_validators.keys():
        try:
            jsonloader.conf.get_validator(step)
        except KeyError:
            raise errors.ConfigValidationException(
                "Unknown validator <{}> found (for registration "
                "authority {})".format(step, ra_name))

    config_check_domains(ra_validators)
    logger.info("Validators OK for registration authority: %s", ra_name)

    ra_fixups = ra_conf.get('fixups', {})

    for step in ra_fixups.keys():
        try:
            jsonloader.conf.get_fixup(step)
        except KeyError:
            raise errors.ConfigValidationException(
                "Unknown fixup <{}> found (for registration "
                "authority {})".format(step, ra_name))

    logger.info("Fixups OK for registration authority: %s", ra_name)


def load_config():
    """Attempt to find and load a JSON configuration file.

    We will search in various locations in order for a valid config file
    to use:

    - the contents of 'ANCHOR_CONF' environment variable
    - a local 'config.json' file in the invocation folder
    - a HOME/.config/anchor/config.json file
    - a /etc/anchor/config.json file
    """
    config_name = 'ANCHOR_CONF'
    local_config_path = 'config.json'
    user_config_path = os.path.join(
        os.environ['HOME'], '.config', 'anchor', 'config.json')

    sys_config_path = os.path.join(os.sep, 'etc', 'anchor', 'config.json')

    if 'registration_authority' not in jsonloader.conf.config:
        config_path = ""
        if config_name in os.environ:
            config_path = os.environ[config_name]
        elif os.path.isfile(local_config_path):
            config_path = local_config_path
        elif os.path.isfile(user_config_path):
            config_path = user_config_path
        elif os.path.isfile(sys_config_path):
            config_path = sys_config_path
        logger = logging.getLogger("anchor")
        logger.info("using config: {}".format(config_path))
        jsonloader.conf.load_file_data(config_path)

        jsonloader.conf.load_extensions()


def setup_app(config):
    # initial logging, will be re-configured later
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    app_conf = dict(config.app)

    load_config()
    validate_config(jsonloader.conf)

    audit.init_audit()

    app = pecan.make_app(
        app_conf.pop('root'),
        logging=config.logging,
        **app_conf
    )

    return paste.translogger.TransLogger(app, setup_console_handler=False)
