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
import stat
import sys

import paste
from paste import translogger  # noqa
import pecan

from anchor import jsonloader

logger = logging.getLogger(__name__)


class ConfigValidationException(Exception):
    pass


def config_check_domains(validator_set):
    for name, step in validator_set.items():
        if 'allowed_domains' in step:
            for domain in step['allowed_domains']:
                if not domain.startswith('.'):
                    raise ConfigValidationException(
                        "Domain that does not start with "
                        "a '.' <{}>".format(domain))


def _check_file_permissions(path):
    # checks that file is owner readable only
    expected_permissions = (stat.S_IRUSR | stat.S_IFREG)  # 0o100400
    st = os.stat(path)
    if st.st_mode != expected_permissions:
        raise ConfigValidationException("CA file: %s has incorrect "
                                        "permissions set, expected "
                                        "owner readable only" % path)


def _check_file_exists(path):
    if not (os.path.isfile(path) and
            os.access(path, os.R_OK)):
        raise ConfigValidationException("could not read file: %s" %
                                        path)


def validate_config(conf):
    for old_name in ['auth', 'ca', 'validators']:
        if old_name in conf.config:
            raise ConfigValidationException("The config seems to be for an "
                                            "old version of Anchor. Please "
                                            "check documentation.")

    if not conf.config.get('registration_authority'):
        raise ConfigValidationException("No registration authorities present")

    if not conf.config.get('signing_ca'):
        raise ConfigValidationException("No signing CA configurations present")

    if not conf.config.get('authentication'):
        raise ConfigValidationException("No authentication methods present")

    for name in conf.registration_authority.keys():
        logger.info("Checking config for registration authority: %s", name)
        validate_registration_authority_config(name, conf)

    for name in conf.signing_ca.keys():
        logger.info("Checking config for signing ca: %s", name)
        validate_signing_ca_config(name, conf)

    for name in conf.authentication.keys():
        logger.info("Checking config for authentication method: %s", name)
        validate_authentication_config(name, conf)


def validate_authentication_config(name, conf):
    auth_conf = conf.authentication[name]

    default_user = "myusername"
    default_secret = "simplepassword"

    if not auth_conf.get('backend'):
        raise ConfigValidationException(
            "Authentication method %s doesn't define backend" % name)

    if auth_conf['backend'] not in ('static', 'keystone', 'ldap'):
        raise ConfigValidationException(
            "Authentication backend % unknown" % (auth_conf['backend'],))

    # Check for anchor being run with default user/secret
    if auth_conf['backend'] == 'static':
        if auth_conf['user'] == default_user:
            logger.warning("default user for static auth in use")
        if auth_conf['secret'] == default_secret:
            logger.warning("default secret for static auth in use")


def validate_signing_ca_config(name, conf):
    ca_conf = conf.signing_ca[name]

    # mandatory CA settings
    ca_config_requirements = ["cert_path", "key_path", "output_path",
                              "signing_hash", "valid_hours"]

    for requirement in ca_config_requirements:
        if requirement not in ca_conf.keys():
            raise ConfigValidationException(
                "CA config missing: %s (for signing CA %s)" % (requirement,
                                                               name))

    # all are specified, check the CA certificate and key are readable with
    # sane permissions
    _check_file_exists(ca_conf['cert_path'])
    _check_file_exists(ca_conf['key_path'])

    _check_file_permissions(ca_conf['key_path'])


def validate_registration_authority_config(ra_name, conf):
    ra_conf = conf.registration_authority[ra_name]
    auth_name = ra_conf.get('authentication')
    if not auth_name:
        raise ConfigValidationException(
            "No authentication configured for registration authority: %s" %
            ra_name)

    if not conf.authentication.get(auth_name):
        raise ConfigValidationException(
            "Authentication method %s configured for registration authority "
            "%s doesn't exist" % (auth_name, ra_name))

    ca_name = ra_conf.get('signing_ca')
    if not ca_name:
        raise ConfigValidationException(
            "No signing CA configuration present for registration authority: "
            "%s" % ra_name)

    if not conf.signing_ca.get(ca_name):
        raise ConfigValidationException(
            "Signing CA %s configured for registration authority %s doesn't "
            "exist" % (ca_name, ra_name))

    if not ra_conf.get("validators"):
        raise ConfigValidationException(
            "No validators configured for registration authority: %s" %
            ra_name)

    ra_validators = ra_conf['validators']

    for step in ra_validators.keys():
        try:
            jsonloader.conf.get_validator(step)
        except KeyError:
            raise ConfigValidationException(
                "Unknown validator <{}> found (for registration "
                "authority {})".format(step, ra_name))

    config_check_domains(ra_validators)
    logger.info("Validators OK for registration authority: %s", ra_name)


def load_config():
    """Attempt to find and load a JSON configuration file.

    We will search in various locations in order for a valid config file
    to use:

    - the contents of 'ANCHOR_CONF' environment variable
    - a local 'config.json' file in the invocation folder
    - a HOME/.config/anchor/config.json file
    - a /etc/anchor/config.json fiile
    """
    config_name = 'ANCHOR_CONF'
    local_config_path = 'config.json'
    user_config_path = os.path.join(
        os.environ['HOME'], '.config', 'anchor', 'config.json')

    try:
        prefix = os.environ['VIRTUAL_ENV']
    except KeyError:
        prefix = ''

    sys_config_path = os.path.join(os.sep, prefix,
                                   'etc', 'anchor', 'config.json')

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

    app = pecan.make_app(
        app_conf.pop('root'),
        logging=config.logging,
        **app_conf
    )

    return paste.translogger.TransLogger(app, setup_console_handler=False)
