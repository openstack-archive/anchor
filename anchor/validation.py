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

from anchor import jsonloader
from anchor.validators import errors
from anchor.validators import internal

logger = logging.getLogger(__name__)

# some validators will be always active because they enforce Anchor design
# ideas rather than user configuration
ENFORCED_VALIDATORS = [
    internal.ca_status
    ]


def _run_validator(name, validator, body, args):
    """Parse the validator tuple, call the validator, and return result.

       :param name: the validator name
       :param validator: the validator callable
       :param body: validator body, directly from config
       :param args: additional arguments to pass to the validator function
       :return: True on success, else False
    """
    # careful to not modify the master copy of args with local params
    new_kwargs = args.copy()
    new_kwargs.update(body)

    # perform the actual check
    logger.debug("_run_validator: checking <%s> with rules: %s", name, body)
    try:
        validator(**new_kwargs)
        logger.debug("_run_validator: success: <%s> ", name)
        return True  # validator passed b/c no exceptions
    except errors.ValidationError as e:
        logger.exception("_run_validator: FAILED:  <%s> - %s", name, e)
        return False


def validate_csr(ra_name, auth_result, csr, request):
    """Validates various aspects of the CSR based on the loaded config.

       The arguments of this method are passed to the underlying validate
       methods. Therefore, some may be optional, depending on which
       validation routines are specified in the configuration.

       :param ra_name: name of the registration authority
       :param auth_result: AuthDetails value from auth.validate
       :param csr: CSR value from certificate_ops.parse_csr
       :param request: pecan request object associated with this action
    """

    ra_conf = jsonloader.config_for_registration_authority(ra_name)
    args = {'auth_result': auth_result,
            'csr': csr,
            'conf': ra_conf,
            'request': request}

    # It is ok if the config doesn't have any validators listed
    valid = {}
    for validator in ENFORCED_VALIDATORS:
        vname = validator.__name__
        valid[vname] = _run_validator(vname, validator, {}, args)

    for vname, options in ra_conf['validators'].items():
        validator = jsonloader.conf.get_validator(vname)
        valid[vname] = _run_validator(vname, validator, options, args)

    return valid
