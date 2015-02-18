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

from .results import AUTH_FAILED

from pecan import conf


def validate(user, secret):
    for auth_type in conf.to_dict().get('auth', {}).keys():
        if conf.auth.get(auth_type):
            module_name = "{}.{}".format(__name__, auth_type)
            module = __import__(module_name, fromlist=[''])
            res = module.login(user, secret)
            if res is not AUTH_FAILED:
                return res

    return AUTH_FAILED
