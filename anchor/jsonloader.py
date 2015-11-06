# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
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

import stevedore

logger = logging.getLogger(__name__)


class AnchorConf():

    def __init__(self, logger):
        '''Attempt to initialize a config dictionary from a JSON file.

        Error out if loading the yaml file fails for any reason.
        :param logger: Logger to be used in the case of errors
        :param config_file: The Anchor JSON config file
        :return: -
        '''

        self._logger = logger
        self._config = {}

    def _load_json_file(self, config_file):
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except IOError:
            logger.error("could not open config file: %s" % config_file)
            raise
        except ValueError:
            logger.error("error parsing config file: %s" % config_file)
            raise

    def load_file_data(self, config_file):
        '''Load a config from a file.'''
        self._config = self._load_json_file(config_file)

    def load_str_data(self, data):
        '''Load a config from string data.'''
        self._config = json.loads(data)

    def load_extensions(self):
        self._signing_backends = stevedore.ExtensionManager(
            "anchor.signing_backends")
        self._validators = stevedore.ExtensionManager("anchor.validators")
        self._authentication = stevedore.ExtensionManager(
            "anchor.authentication")
        self._fixups = stevedore.ExtensionManager("anchor.fixups")

    def get_signing_backend(self, name):
        return self._signing_backends[name].plugin

    def get_validator(self, name):
        return self._validators[name].plugin

    def get_authentication(self, name):
        return self._authentication[name].plugin

    def get_fixup(self, name):
        return self._fixups[name].plugin

    @property
    def config(self):
        '''Property to return the config dictionary

        :return: Config dictionary
        '''
        return self._config

    def __getattr__(self, name):
        try:
            return self._config[name]
        except KeyError:
            raise AttributeError("'AnchorConf' object has no attribute '%s'" %
                                 name)


conf = AnchorConf(logger)


def config_for_audit():
    """Get configuration for a given name."""
    try:
        return conf.audit
    except AttributeError:
        # it's ok not to configure audit
        return None


def config_for_registration_authority(ra_name):
    """Get configuration for a given name."""
    return conf.registration_authority[ra_name]


def authentication_for_registration_authority(ra_name):
    """Get authentication config for a given name.

    This is only supposed to be called after config validation. All the right
    elements are expected to be in place.
    """
    auth_name = conf.registration_authority[ra_name]['authentication']
    return conf.authentication[auth_name]


def signing_ca_for_registration_authority(ra_name):
    """Get signing ca config for a given name.

    This is only supposed to be called after config validation. All the right
    elements are expected to be in place.
    """
    ca_name = conf.registration_authority[ra_name]['signing_ca']
    return conf.signing_ca[ca_name]


def registration_authority_names():
    """List the names of supported registration authorities."""
    return conf.registration_authority.keys()
