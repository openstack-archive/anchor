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
import os

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

    def _copy_default_settings(self):
        instances = self.config.get('instances', {})
        for instance_name in instance_names():
            instances[instance_name].setdefault('auth',
                                                self.config.get('auth'))
            instances[instance_name].setdefault('ca',
                                                self.config.get('ca'))

    def load_file_data(self, config_file):
        '''Load a config from a file.'''
        self._config = self._load_json_file(config_file)
        self._config.setdefault('instances', {})
        self._copy_default_settings()

    def load_str_data(self, data):
        '''Load a config from string data.'''
        self._config = json.loads(data)
        self._config.setdefault('instances', {})
        self._copy_default_settings()

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


def for_instance(name):
    return conf.instances[name]


def instance_names():
    return conf.instances.keys()
