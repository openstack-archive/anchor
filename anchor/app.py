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


def validate_config(conf):
    if not hasattr(conf, "auth") or not conf.auth:
        raise ConfigValidationException("No authentication configured")

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
