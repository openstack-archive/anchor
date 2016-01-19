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
import os
import time
import uuid

import pecan
from webob import exc as http_status

from anchor import jsonloader
from anchor import validation
from anchor.X509 import certificate
from anchor.X509 import extension
from anchor.X509 import signing_request
from anchor.X509 import utils


logger = logging.getLogger(__name__)


# we only support the PEM encoding for now, but this may grow
# to support things like DER in the future
VALID_ENCODINGS = ['pem']


class SigningError(Exception):
    pass


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
        out_req = signing_request.X509Csr.from_buffer(csr)
        return out_req
    except Exception as e:
        logger.exception("Exception while parsing the CSR: %s", e)
        pecan.abort(400, "CSR cannot be parsed")


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
    try:
        valid = validation.validate_csr(ra_name, auth_result, csr, request)
    except Exception as e:
        logger.exception("Error running validators: %s", e)
        pecan.abort(500, "Internal Validation Error")

    if not all(list(valid.values())):
        pecan.abort(400, "CSR failed validation")


def certificate_fingerprint(cert_pem, hash_name):
    """Get certificate fingerprint."""
    cert = certificate.X509Certificate.from_buffer(cert_pem)
    return cert.get_fingerprint(hash_name)


def get_ca(ra_name):
    ca_conf = jsonloader.signing_ca_for_registration_authority(ra_name)

    ca_path = ca_conf.get('cert_path')
    if not ca_path:
        pecan.abort(404, "CA certificate not available")

    with open(ca_path) as f:
        return f.read()


def dispatch_sign(ra_name, csr):
    """Dispatch the sign call to the configured backend.

    :param csr: X509 certificate signing request
    :return: signed certificate in PEM format
    """
    ca_conf = jsonloader.signing_ca_for_registration_authority(ra_name)
    backend_name = ca_conf.get('backend', 'anchor')
    sign_func = jsonloader.conf.get_signing_backend(backend_name)
    try:
        cert_pem = sign_func(csr, ca_conf)
    except http_status.HTTPException:
        logger.exception("Failed to sign certificate")
        raise
    except Exception:
        logger.exception("Failed to sign the certificate")
        pecan.abort(500, "certificate signing error")

    fingerprint = certificate_fingerprint(cert_pem, 'sha256')
    if ca_conf.get('output_path') is not None:
        path = os.path.join(
            ca_conf['output_path'],
            '%s.crt' % fingerprint)

        logger.info("Saving certificate to: %s", path)

        with open(path, "w") as f:
            f.write(cert_pem)

    return cert_pem, fingerprint


def _run_fixup(name, body, args):
    """Parse the fixup tuple, call the fixup, and return the new csr.

       :param name: the fixup name
       :param body: fixup body, directly from config
       :param args: additional arguments to pass to the fixup function
       :return: the fixed csr
    """
    # careful to not modify the master copy of args with local params
    new_kwargs = args.copy()
    new_kwargs.update(body)

    # perform the actual check
    logger.debug("_run_fixup: fixup <%s> with arguments: %s", name, body)
    try:
        fixup = jsonloader.conf.get_fixup(name)
        new_csr = fixup(**new_kwargs)
        logger.debug("_run_fixup: success: <%s> ", name)
        return new_csr
    except Exception:
        logger.exception("_run_fixup: FAILED: <%s>", name)
        return None


def fixup_csr(ra_name, csr, request):
    """Apply configured changes to the certificate.

    :param ra_name: registration authority name
    :param csr: X509 certificate signing request
    :param request: pecan request
    """
    ra_conf = jsonloader.config_for_registration_authority(ra_name)
    args = {'csr': csr,
            'conf': ra_conf,
            'request': request}

    fixups = ra_conf.get('fixups', {})
    try:
        for fixup_name, fixup in fixups.items():
            new_csr = _run_fixup(fixup_name, fixup, args)
            if new_csr is None:
                pecan.abort(500, "Could not finish all required modifications")
            if not isinstance(new_csr, signing_request.X509Csr):
                logger.error("Fixup %s returned incorrect object", fixup_name)
                pecan.abort(500, "Could not finish all required modifications")
            args['csr'] = new_csr

    except http_status.HTTPInternalServerError:
        raise

    except Exception:
        logger.exception("Failed to execute fixups")
        pecan.abort(500, "Could not finish all required modifications")

    return args['csr']


def sign(csr, ca_conf):
    """Generate an X.509 certificate and sign it.

    :param csr: X509 certificate signing request
    :param ca_conf: signing CA configuration
    :return: signed certificate in PEM format
    """
    try:
        ca = certificate.X509Certificate.from_file(
            ca_conf['cert_path'])
    except Exception as e:
        raise SigningError("Cannot load the signing CA: %s" % (e,))

    try:
        key = utils.get_private_key_from_file(ca_conf['key_path'])
    except Exception as e:
        raise SigningError("Cannot load the signing CA key: %s" % (e,))

    new_cert = certificate.X509Certificate()
    new_cert.set_version(2)

    start_time = int(time.time())
    end_time = start_time + (ca_conf['valid_hours'] * 60 * 60)
    new_cert.set_not_before(start_time)
    new_cert.set_not_after(end_time)

    new_cert.set_pubkey(pkey=csr.get_pubkey())
    new_cert.set_subject(csr.get_subject())
    new_cert.set_issuer(ca.get_subject())

    serial = int(uuid.uuid4().hex, 16)
    new_cert.set_serial_number(serial)

    exts = csr.get_extensions()

    ext_i = 0
    for ext in exts:
        # this check is separate from standards validator - the signing backend
        # may know about more/fewer extensions than we do
        if ext.get_oid() not in extension.EXTENSION_CLASSES.keys():
            if ext.get_critical():
                logger.warning("CSR submitted with unknown extension oid %s, "
                               "refusing to sign", ext.get_oid())
                raise SigningError("Unknown critical extension %s" % (
                    ext.get_oid(),))
            else:
                logger.info("CSR submitted with non-critical unknown oid %s, "
                            "not including extension", (ext.get_oid(),))
        else:
            logger.info("Adding certificate extension: %i %s", ext_i, str(ext))
            new_cert.add_extension(ext, ext_i)
            ext_i += 1

    logger.info("Signing certificate for <%s> with serial <%s>",
                csr.get_subject(), serial)

    new_cert.sign(key, ca_conf['signing_hash'])

    cert_pem = new_cert.as_pem()

    return cert_pem
