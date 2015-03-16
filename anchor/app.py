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

import os
import stat

import paste
from paste import translogger  # noqa
import pecan
import validators

from anchor import jsonloader


class ConfigValidationException(Exception):
    pass


def config_check_domains(conf):
    # gc.validators[0]['steps'][0][1]['allowed_domains']

    for validator in conf.validators:
        for step in validator['steps']:
            if 'allowed_domains' in step[1]:
                for domain in step[1]['allowed_domains']:
                    if not domain.startswith('.'):
                        raise ConfigValidationException(
                            "Domain that does not start with "
                            "a '.' <%s>", domain)


def _check_file_permissions(path):
    # checks that file is owner readable only
    expected_permissions = (stat.S_IRUSR | stat.S_IFREG)  # 0o100400
    st = os.stat(path)
    if st.st_mode != expected_permissions:
        raise ConfigValidationException("CA file: %s has incorrect "
                                        "permissions set, expected "
                                        "owner readable only" % path)


def validate_config(conf):
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

    if not (os.path.isfile(conf.ca['cert_path']) and
            os.access(conf.ca['cert_path'], os.R_OK)):
        raise ConfigValidationException("could not read CA cert file: %s" %
                                        conf.ca['cert_path'])
    if not (os.path.isfile(conf.ca['key_path']) and
            os.access(conf.ca['key_path'], os.R_OK)):
        raise ConfigValidationException("could not read CA private key file:"
                                        " %s" % conf.ca['key_path'])

    _check_file_permissions(conf.ca['cert_path'])
    _check_file_permissions(conf.ca['key_path'])

    if not hasattr(conf, "validators"):
        raise ConfigValidationException("No validators configured")

    for i, validators_list in enumerate(conf.validators):
        name = validators_list.get("name")
        if not name:
            raise ConfigValidationException("Validator set %i is missing a "
                                            "name", i + 1)

        if not validators_list.get("steps"):
            raise ConfigValidationException("Validator set <%s> is missing "
                                            "validation steps", name)

        for step in validators_list["steps"]:
            if len(step) == 0:
                raise ConfigValidationException("Validator set <%s> contains "
                                                "a step with no validator "
                                                "name", name)

            if not hasattr(validators, step[0]):
                raise ConfigValidationException("Validator set <%s> contains "
                                                "an unknown validator <%s>",
                                                name, step[0])

    config_check_domains(conf)


def setup_app(config):
    app_conf = dict(config.app)

    validate_config(jsonloader.conf)

    app = pecan.make_app(
        app_conf.pop('root'),
        logging=config.logging,
        **app_conf
    )
    return paste.translogger.TransLogger(app, setup_console_handler=False)
