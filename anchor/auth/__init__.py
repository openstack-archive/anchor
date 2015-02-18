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

from pecan import abort
from pecan import conf

# One time, on import, we want to safely build a list of the auth
# modules listed in the config that we should be using for validate.
# This technique is "safe" because it will not fail, even if there
# is no config defined. It will also not fail if the config is
# imcomplete or malformed.
AUTH_MODULES = []
try:
    for auth_type in conf.to_dict().get('auth', {}).keys():
        try:
            module_name = "{}.{}".format(__name__, auth_type)
            module = __import__(module_name, fromlist=[''])
            AUTH_MODULES.append(module)
        except TypeError:
            pass  # malformed config, but try next auth type in config
except AttributeError:
    pass  # malformed config


def validate(user, secret):
    """Top-level authN entry point.

       This will return an AuthDetails object or abort. This will only
       check that a single auth method. That method will either succeed
       or fail.

       :param user: user provided user name
       :param secret: user provided secret (password or token)
       :return: AuthDetails if authenticated or aborts
    """
    for module in AUTH_MODULES:
        res = module.login(user, secret)
        if res:
            return res

    # we should only get here if a module failed to abort
    abort(401, "authentication failure")
