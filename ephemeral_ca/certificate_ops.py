import M2Crypto
import logging
import os
import time
import uuid
from pecan import conf
from . import validators

logger = logging.getLogger(__name__)


def parse_csr(csr, encoding):
    try:
        if encoding != 'pem' or csr is None:
            return None

        return M2Crypto.X509.load_request_string(csr.encode('ascii'))
    except Exception:
        logger.exception("failed while parsing the CSR")
        return None


def validate_csr(auth_result, csr, request):
    args = {'auth_result': auth_result, 'csr': csr, 'conf': conf, 'request': request}
    for validator_steps in conf.validators:
        logger.debug("Checking validators set <%s>", validator_steps.get("name"))
        valid = True

        for validator in validator_steps['steps']:
            if not isinstance(validator, tuple):
                logger.error("Validator should be defined by a tuple (got '%s' instead)", validator)
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
            except validators.ValidationError as e:
                logger.debug("Validation failed: %s", e)
                valid = False
                break

        if valid:
            # request passed all the tests here
            return

    raise validators.ValidationError("All validator sets failed")


def sign(csr):
    try:
        ca = M2Crypto.X509.load_cert(conf.ca["cert_path"])
    except IOError:
        logger.exception("Cannot load the signing CA")
        return None

    try:
        key = M2Crypto.EVP.load_key(conf.ca["key_path"])
    except IOError:
        logger.exception("Cannot load the signing CA")
        return None

    new_cert = M2Crypto.X509.X509()
    new_cert.set_version(0)

    now = int(time.time())
    start_time = M2Crypto.ASN1.ASN1_UTCTIME()
    start_time.set_time(now)
    end_time = M2Crypto.ASN1.ASN1_UTCTIME()
    end_time.set_time(now+(conf.ca['valid_hours']*60*60))

    new_cert.set_not_before(start_time)
    new_cert.set_not_after(end_time)

    new_cert.set_pubkey(pkey=csr.get_pubkey())
    new_cert.set_subject(csr.get_subject())
    new_cert.set_issuer(ca.get_subject())
    serial = uuid.uuid4().get_hex()
    new_cert.set_serial_number(int(serial, 16))

    for ext in (csr.get_extensions() or []):
        new_cert.add_ext(ext)

    logger.info("Signing certificate for <%s> with serial <%s>", csr.get_subject(), serial)
    new_cert.sign(key, conf.ca['signing_hash'])

    new_cert.save(os.path.join(
        conf.ca['output_path'],
        '%s.crt' % new_cert.get_fingerprint(conf.ca['signing_hash'])))

    return new_cert.as_pem()
