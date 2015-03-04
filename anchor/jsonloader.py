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

import json
import logging
import sys


logger = logging.getLogger(__name__)


class AnchorConf():

    def __init__(self, logger, config_file):
        '''Attempt to initialize a config dictionary from a yaml file.

        Error out if loading the yaml file fails for any reason.
        :param logger: Logger to be used in the case of errors
        :param config_file: The Anchor yaml config file
        :return: -
        '''

        self._logger = logger
        self._config = {}

        try:
            f = open(config_file, 'r')
        except IOError:
            logger.error("could not open config file: %s" % config_file)
            sys.exit(2)
        else:
            # JSON parser does its own exception handling
            self._config = json.load(f)

    @property
    def config(self):
        '''Property to return the config dictionary

        :return: Config dictionary
        '''
        return self._config

    def __getattr__(self, name):
        return self._config[name]


conf = AnchorConf(logger, "config.json")
