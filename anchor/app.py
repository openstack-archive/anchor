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
import os
import stat
import sys

import paste
from paste import translogger  # noqa
import pecan
import validators

from anchor import jsonloader

logger = logging.getLogger(__name__)


class ConfigValidationException(Exception):
    pass


def config_check_domains(validator_set):
    for name, step in validator_set.iteritems():
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
    logger = logging.getLogger("anchor")

    if not hasattr(conf, "auth") or not conf.auth:
        raise ConfigValidationException("No authentication configured")

    if not hasattr(conf, "ca") or not conf.ca:
        raise ConfigValidationException("No ca configuration present")

    # mandatory CA settings
    ca_config_requirements = ["cert_path", "key_path", "output_path",
                              "signing_hash", "valid_hours"]

    for requirement in ca_config_requirements:
        if requirement not in conf.ca.keys():
            raise ConfigValidationException("CA config missing: %s" %
                                            requirement)

    # all are specified, check the CA certificate and key are readable with
    # sane permissions
    _check_file_exists(conf.ca['cert_path'])
    _check_file_exists(conf.ca['key_path'])

    _check_file_permissions(conf.ca['cert_path'])
    _check_file_permissions(conf.ca['key_path'])

    if not hasattr(conf, "validators"):
        raise ConfigValidationException("No validators configured")

    logger.info("Found {} validator sets.".format(len(conf.validators)))
    for name, validator_set in conf.validators.iteritems():
        logger.info("Checking validator set <{}> ....".format(name))
        if len(validator_set) == 0:
            raise ConfigValidationException(
                "Validator set <{}> is empty".format(name))

        for step in validator_set.keys():
            if not hasattr(validators, step):
                raise ConfigValidationException(
                    "Validator set <{}> contains an "
                    "unknown validator <{}>".format(name, step))

    config_check_domains(validator_set)
    logger.info("Validator set OK")


def check_default_auth(conf):
    default_user = "myusername"
    default_secret = "simplepassword"

    # Check for anchor being run with default user/secret
    if 'static' in conf.auth.keys():
        if conf.auth['static']['user'] == default_user:
            logger.warn("default user for static auth in use")
        if conf.auth['static']['secret'] == default_secret:
            logger.warn("default secret for static auth in use")


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

    sys_config_path = os.path.join(os.sep, 'etc', 'anchor', 'config.json')

    if 'auth' not in jsonloader.conf.config:
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

    check_default_auth(jsonloader.conf)

    return paste.translogger.TransLogger(app, setup_console_handler=False)
