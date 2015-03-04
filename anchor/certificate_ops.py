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

import ipdb

import logging
import os
import sys
import time
import uuid

import pecan

from anchor import jsonloader
from anchor import validators
from anchor.X509 import certificate
from anchor.X509 import signing_request
from anchor.X509 import utils as X509_utils


logger = logging.getLogger(__name__)


# we only support the PEM encoding for now, but this may grow
# to support things like DER in the future
VALID_ENCODINGS = ['pem']


def parse_csr(csr, encoding):
    """Loads the user provided CSR into the backend X509 library.

       :param csr: CSR as provided by the API user
       :param encoding: encoding for the CSR (must be PEM today)
       :return: CSR object from backend X509 library or aborts
    """
    # validate untrusted input
    if str(encoding).lower() not in VALID_ENCODINGS:
        logger.error("parse_csr failed: bad encoding ({})".format(encoding))
        pecan.abort(400, "invalid CSR")

    if csr is None:
        logger.error("parse_csr failed: missing CSR")
        pecan.abort(400, "invalid CSR")

    # load the CSR into the backend X509 library
    try:
        out_req = signing_request.X509Csr()
        out_req.from_buffer(csr)
        return out_req
    except Exception as e:
        logger.exception("Exception while parsing the CSR: %s", e)
        pecan.abort(400, "CSR cannot be parsed")


def _run_validator(validator_step, args):
    """Parse the validator tuple, call the validator, and return result.

       :param validator_step: validator tuple directly from the config
       :param args: additional arguments to pass to the validator function
       :return: True on success, else False
    """
    function_name = validator_step[0]
    params = validator_step[1]

    # make sure the requested validator exists
    if not hasattr(validators, function_name):
        logger.error("_run_validator: no validator method {}".format(tup))
        return False

    # careful to not modify the master copy of args with local params
    new_kwargs = args.copy()
    new_kwargs.update(params)

    # perform the actual check
    logger.debug("_run_validator: checking {}".format(function_name))
    try:
        validator = getattr(validators, function_name)
        validator(**new_kwargs)
        return True  # validator passed b/c no exceptions
    except validators.ValidationError as e:
        logger.error("_run_validator: validation failed %s", e)
        return False


def validate_csr(auth_result, csr, request):
    """Validates various aspects of the CSR based on the loaded config.

       The arguments of this method are passed to the underlying validate
       methods. Therefore, some may be optional, depending on which
       validation routines are specified in the configuration.

       :param auth_result: AuthDetails value from auth.validate
       :param csr: CSR value from certificate_ops.parse_csr
       :param request: pecan request object associated with this action
    """
    # NOTE(tkelsey): im not so sure we want to pass all this lot through
    # to the validator, seems like far more than we should need. Also, the
    # config block breaks when passed through as key word args.
    #
    args = {'auth_result': auth_result,
            'csr': csr,
            # 'conf': jsonloader.conf,
            'request': request}

    # It is ok if the config doesn't have any validators listed
    # so we set the initial state to valid.
    valid = True

    for vset in jsonloader.conf.validators:
        logger.debug("validate_csr: checking {}".format(vset.get("name")))

        results = [_run_validator(x, args) for x in vset['steps']]
        results.append(valid)  # track previous failures
        valid = all(results)

    # valid here says that either (1) we didn't run any tests, or (2) we
    # ran some tests and they all passed. Either way, we can just return.
    if valid:
        return

    # something failed, return a 400 to the client
    pecan.abort(400, "CSR failed validation")


def sign(csr):

    try:
        ca = certificate.X509Certificate()
        ca.from_file(jsonloader.conf.ca["cert_path"])
    except Exception as e:
        logger.exception("Cannot load the signing CA: %s", e)
        pecan.abort(500, "certificate signing error")

    try:
        key_data = None
        with open(jsonloader.conf.ca["key_path"]) as f:
            key_data = f.read()
        key = X509_utils.load_pem_private_key(key_data)
    except Exception as e:
        logger.exception("Cannot load the signing CA key: %s", e)
        pecan.abort(500, "certificate signing error")

    new_cert = certificate.X509Certificate()
    new_cert.set_version(2)

    start_time = int(time.time())
    end_time = start_time + (jsonloader.conf.ca['valid_hours'] * 60 * 60)
    new_cert.set_not_before(start_time)
    new_cert.set_not_after(end_time)

    new_cert.set_pubkey(pkey=csr.get_pubkey())
    new_cert.set_subject(csr.get_subject())
    new_cert.set_issuer(ca.get_subject())

    # NOTE(tkelsey): this needs to be in the range of an int
    serial = int(int(uuid.uuid4().get_hex(), 16) % sys.maxsize)
    new_cert.set_serial_number(serial)

    exts = csr.get_extensions()
    for i, ext in enumerate(exts):
        logger.info("Adding certificate extension: %i %s", i, str(ext))
        new_cert.add_extension(ext, i)

    logger.info("Signing certificate for <%s> with serial <%s>",
                csr.get_subject(), serial)

    new_cert.sign(key, jsonloader.conf.ca['signing_hash'])

    path = os.path.join(
        jsonloader.conf.ca['output_path'],
        '%s.crt' % new_cert.get_fingerprint(
            jsonloader.conf.ca['signing_hash']))

    logger.info("Saving certificate to: %s", path)
    new_cert.save(path)

    # return cert from memory if/when X509 lib supports it
    with open(path) as f:
        cert = f.read()
        if cert:
            return cert

    pecan.abort(500, "certificate signing error")
