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


def validate_csr(auth_result, csr):
    args = {'auth_result': auth_result, 'csr': csr, 'conf': conf}
    for validator in conf.validators:
        if not isinstance(validator, tuple):
            raise Exception("Validator should be defined by a tuple (got '%s' instead)" % (validator,))
        elif len(validator) == 1:
            validator_name, params = validator[0], {}
        elif len(validator) == 2:
            validator_name, params = validator
        elif len(validator) > 2:
            raise Exception("Validator config incorrect: '%s'" % (validator,))

        if not hasattr(validators, validator_name):
            raise Exception("Could not find validator named '%s'" % (validator,))
        new_kwargs = args.copy()
        new_kwargs.update(params)
        getattr(validators, validator_name)(**new_kwargs)


def sign(csr):
    ca = M2Crypto.X509.load_cert(conf.ca["cert_path"])
    key = M2Crypto.EVP.load_key(conf.ca["key_path"])

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
    new_cert.set_serial_number(int(uuid.uuid4().get_hex(), 16))

    for ext in (csr.get_extensions() or []):
        new_cert.add_ext(ext)

    new_cert.sign(key, conf.ca['signing_hash'])

    new_cert.save(os.path.join(
        conf.ca['output_path'],
        '%s.crt' % new_cert.get_fingerprint(conf.ca['signing_hash'])))

    return new_cert.as_pem()
