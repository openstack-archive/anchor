from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

from anchor import errors
from anchor import signers
from anchor import util
from anchor.X509 import utils as x509_utils


SIGNER_CONSTRUCTION = {
    ('RSA', 'SHA224'): (lambda key: key.signer(padding.PKCS1v15(),
                                               hashes.SHA224())),
    ('RSA', 'SHA256'): (lambda key: key.signer(padding.PKCS1v15(),
                                               hashes.SHA256())),
    ('RSA', 'SHA384'): (lambda key: key.signer(padding.PKCS1v15(),
                                               hashes.SHA384())),
    ('RSA', 'SHA512'): (lambda key: key.signer(padding.PKCS1v15(),
                                               hashes.SHA512())),
    ('DSA', 'SHA224'): (lambda key: key.signer(hashes.SHA224())),
    ('DSA', 'SHA256'): (lambda key: key.signer(hashes.SHA256())),
}


def conf_validator(name, ca_conf):
    # mandatory CA settings
    ca_config_requirements = ["cert_path", "key_path", "output_path",
                              "signing_hash", "valid_hours"]

    for requirement in ca_config_requirements:
        if requirement not in ca_conf.keys():
            raise errors.ConfigValidationException(
                "CA config missing: %s (for signing CA %s)" % (requirement,
                                                               name))

    # all are specified, check the CA certificate and key are readable with
    # sane permissions
    util.check_file_exists(ca_conf['cert_path'])
    util.check_file_exists(ca_conf['key_path'])

    util.check_file_permissions(ca_conf['key_path'])


def make_signer(key, encryption, md):
    signer = SIGNER_CONSTRUCTION.get((encryption, md.upper()))
    if signer is None:
        raise signers.SigningError(
            "Unknown hash/encryption combination (%s/%s)" % (md, encryption))
    signer = signer(key)

    def cryptography_io_signer(to_sign):
        signer.update(to_sign)
        return signer.finalize()

    return cryptography_io_signer


@signers.config_validator(conf_validator)
def sign(csr, ca_conf):
    try:
        key = x509_utils.get_private_key_from_file(ca_conf['key_path'])
    except Exception as e:
        raise signers.SigningError("Cannot load the signing CA key: %s" % (e,))

    if isinstance(key, rsa.RSAPrivateKey):
        encryption = 'RSA'
    elif isinstance(key, dsa.DSAPrivateKey):
        encryption = 'DSA'
    else:
        raise signers.SigningError("Unknown key type: %s" % (key.__class__,))

    signer = make_signer(key, encryption, ca_conf['signing_hash'])
    return signers.sign_generic(csr, ca_conf, encryption, signer)
