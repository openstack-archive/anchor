from cryptography.hazmat import backends as cio_backends
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import encoder
from pyasn1.type import univ as asn1_univ
from pyasn1_modules import rfc2315

from anchor import errors
from anchor import signers
from anchor import util


def import_pkcs():
    # separate function for mocking the import failure
    return __import__("PyKCS11")


def conf_validator(name, ca_conf):
    # mandatory CA settings
    ca_config_requirements = ["cert_path", "output_path", "signing_hash",
                              "valid_hours", "slot", "pin", "key_id",
                              "pkcs11_path"]

    for requirement in ca_config_requirements:
        if requirement not in ca_conf.keys():
            raise errors.ConfigValidationException(
                "CA config missing: %s (for signing CA %s)" % (requirement,
                                                               name))

    # all are specified, check the CA certificate and key are readable with
    # sane permissions
    util.check_file_exists(ca_conf['cert_path'])
    util.check_file_exists(ca_conf['pkcs11_path'])

    # PyKCS11 is an optional dependency
    try:
        PyKCS11 = import_pkcs()
    except ImportError:
        raise errors.ConfigValidationException(
            "PyKCS11 library cannot be imported")

    # library at the selected path should be possible to load
    try:
        pkcslib = PyKCS11.PyKCS11Lib()
        pkcslib.load(ca_conf['pkcs11_path'])
    except PyKCS11.PyKCS11Error:
        raise errors.ConfigValidationException(
            "Selected pkcs11 library failed to load")

    slot = ca_conf['slot']
    slots = pkcslib.getSlotList()
    if slot not in slots:
        raise errors.ConfigValidationException(
            "Slot %s cannot be found in the pkcs11 store" % slot)

    try:
        session = pkcslib.openSession(slot)
        session.login(ca_conf['pin'])
    except PyKCS11.PyKCS11Error:
        raise errors.ConfigValidationException(
            "Cannot login to the selected slot")


def make_signer(key_id, slot, pin, pkcs11_path, md):
    HASH_OIDS = {
        'SHA256': asn1_univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1'),
        'SHA384': asn1_univ.ObjectIdentifier('2.16.840.1.101.3.4.2.2'),
        'SHA512': asn1_univ.ObjectIdentifier('2.16.840.1.101.3.4.2.3'),
        'SHA224': asn1_univ.ObjectIdentifier('2.16.840.1.101.3.4.2.4'),
    }

    PyKCS11 = import_pkcs()
    try:
        pkcslib = PyKCS11.PyKCS11Lib()
        pkcslib.load(pkcs11_path)
        session = pkcslib.openSession(slot)
        session.login(pin)
    except PyKCS11.PyKCS11Error:
        raise signers.SigningError("Could not setup the pkcs11 session")

    keys = session.findObjects((
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
        (PyKCS11.CKA_SIGN, True),
        (PyKCS11.CKA_ID, key_id),
        ))
    if not keys:
        raise signers.SigningError("Cannot find the requested key")
    key = keys[0]
    cio_hash = getattr(hashes, md, None)
    if not cio_hash:
        raise signers.SigningError("Requested hash is not supported")

    h = hashes.Hash(cio_hash(), cio_backends.default_backend())

    def pkcs11_signer(to_sign):
        pkcslib.getInfo  # just to keep pkcslib in scope, it's a NOOP
        h.update(to_sign)
        di = rfc2315.DigestInfo()
        di['digestAlgorithm'] = None
        di['digestAlgorithm'][0] = HASH_OIDS[md]
        di['digest'] = h.finalize()
        signature = bytes(session.sign(key, encoder.encode(di),
                                       PyKCS11.MechanismRSAPKCS1))
        session.logout()
        return signature

    return pkcs11_signer


@signers.config_validator(conf_validator)
def sign(csr, ca_conf):
    slot = ca_conf['slot']
    pin = ca_conf['pin']
    pkcs11_path = ca_conf['pkcs11_path']
    key_id = [int(ca_conf['key_id'][i:i+2], 16) for
              i in range(0, len(ca_conf['key_id']), 2)]
    signing_hash = ca_conf['signing_hash'].upper()

    signer = make_signer(key_id, slot, pin, pkcs11_path, signing_hash)
    return signers.sign_generic(csr, ca_conf, 'RSA', signer)
