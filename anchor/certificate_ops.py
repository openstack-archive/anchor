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

from X509 import certificate
from X509 import signing_request
from X509 import utils as X509_utils

import logging
import os
import sys
import time
import uuid

from pecan import abort
from pecan import conf

from . import validators


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
        logger.error("parse_csr failed: invalid encoding ({})".format(encoding))
        abort(400, "invalid CSR")

    if csr is None:
        logger.error("parse_csr failed: missing CSR")
        abort(400, "invalid CSR")

    # load the CSR into the backend X509 library
    try:
        out_req = signing_request.X509Csr()
        out_req.from_buffer(csr)
        return out_req
    except Exception as e:
        logger.exception("parse_csr exception while parsing the CSR: %s", e)
        abort(400, "invalid CSR")


def validate_csr(auth_result, csr, request):
    args = {'auth_result': auth_result,
            'csr': csr,
            'conf': conf,
            'request': request}

    # It is ok if the config doesn't have any validators listed
    # so we set the initial state to valid.
    valid = True

    for validator_set in conf.validators:
        logger.debug("Checking validators set <%s>",
                     validator_set.get("name"))

        # there is at least one validator in the config, so set valid to
        # false until we see the validator pass
        valid = False

        for validator in validator_set['steps']:
            if not isinstance(validator, tuple):
                logger.error("Validator should be defined by a tuple"
                             " (got '%s' instead)", validator)
                break
            elif len(validator) == 1:
                validator_name, params = validator[0], {}
            elif len(validator) == 2:
                validator_name, params = validator
            elif len(validator) > 2:
                logger.error("Validator config incorrect: '%s'", validator)
                break

            if not hasattr(validators, validator_name):
                logger.error("Could not find validator named '%s'", validator)
                break

            logger.debug("Checking step <%s>", validator_name)

            new_kwargs = args.copy()
            new_kwargs.update(params)
            try:
                getattr(validators, validator_name)(**new_kwargs)
                valid = True  # validator passed b/c no exceptions
            except validators.ValidationError as e:
                logger.debug("Validation failed: %s", e)
                valid = False
                break

    # valid here says that either (1) we didn't run any tests, or (2) we
    # ran some tests and they all passed. Either way, we can just return.
    if valid:
        return

    # something failed, return a 400 to the client
    abort(400, "CSR failed validation")


def sign(csr):

    try:
        ca = certificate.X509Certificate()
        ca.from_file(conf.ca["cert_path"])
    except Exception as e:
        logger.exception("Cannot load the signing CA: %s", e)
        abort(500, "certificate signing error")

    try:
        key_data = None
        with open(conf.ca["key_path"]) as f:
            key_data = f.read()
        key = X509_utils.load_pem_private_key(key_data)
    except Exception as e:
        logger.exception("Cannot load the signing CA key: %s", e)
        abort(500, "certificate signing error")

    new_cert = certificate.X509Certificate()
    new_cert.set_version(2)

    start_time = int(time.time())
    end_time = start_time + (conf.ca['valid_hours'] * 60 * 60)
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

    new_cert.sign(key, conf.ca['signing_hash'])

    path = os.path.join(
        conf.ca['output_path'],
        '%s.crt' % new_cert.get_fingerprint(conf.ca['signing_hash']))

    logger.info("Saving certificate to: %s", path)
    new_cert.save(path)

    # return cert from memory if/when X509 lib supports it
    with open(path) as f:
        cert = f.read()
        if cert:
            return cert

    abort(500, "certificate signing error")
