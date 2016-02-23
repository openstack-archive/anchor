import logging
import time
import uuid

from anchor.X509 import certificate
from anchor.X509 import extension


logger = logging.getLogger(__name__)


def config_validator(val):
    def patcher(f):
        setattr(f, "_config_validator", val)
        return f
    return patcher


class SigningError(Exception):
    pass


def sign_generic(csr, ca_conf, encryption, signer):
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
            # authority id will be replaced with current signer
            # this cannot be a fixup, because they don't get access to the CA
            if isinstance(ext, extension.X509ExtensionAuthorityKeyId):
                continue

            new_cert.add_extension(ext, ext_i)
            ext_i += 1

    ca_exts = ca.get_extensions(extension.X509ExtensionSubjectKeyId)
    auth_key_id = extension.X509ExtensionAuthorityKeyId()
    if ca_exts:
        auth_key_id.set_key_id(ca_exts[0].get_key_id())
    else:
        auth_key_id.set_key_id(ca.get_key_id())
    new_cert.add_extension(auth_key_id, ext_i)

    logger.info("Signing certificate for <%s> with serial <%s>",
                csr.get_subject(), serial)

    new_cert.sign(encryption, ca_conf['signing_hash'], signer)

    cert_pem = new_cert.as_pem()

    return cert_pem
