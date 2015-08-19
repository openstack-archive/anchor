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

import base64
import binascii
import io

from cryptography.hazmat import backends as cio_backends
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import univ as asn1_univ
from pyasn1_modules import pem
from pyasn1_modules import rfc2459  # X509v3

from anchor.X509 import errors
from anchor.X509 import extension
from anchor.X509 import name
from anchor.X509 import utils


SIGNING_ALGORITHMS = {
    ('RSA', 'MD5'): rfc2459.md5WithRSAEncryption,
    ('RSA', 'SHA1'): rfc2459.sha1WithRSAEncryption,
    ('RSA', 'SHA224'): asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.14'),
    ('RSA', 'SHA256'): asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.11'),
    ('RSA', 'SHA384'): asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.12'),
    ('RSA', 'SHA512'): asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.13'),
    ('DSA', 'SHA1'): rfc2459.id_dsa_with_sha1,
    ('DSA', 'SHA224'): asn1_univ.ObjectIdentifier('2.16.840.1.101.3.4.3.1'),
    ('DSA', 'SHA256'): asn1_univ.ObjectIdentifier('2.16.840.1.101.3.4.3.2'),
}


class X509CertificateError(errors.X509Error):
    """Specific error for X509 certificate operations."""
    pass


class X509Certificate(object):
    """X509 certificate class."""
    def __init__(self, certificate=None):
        if certificate is None:
            self._cert = rfc2459.Certificate()
            self._cert['tbsCertificate'] = rfc2459.TBSCertificate()
        else:
            self._cert = certificate

    @staticmethod
    def from_open_file(f):
        try:
            der_content = pem.readPemFromFile(f)
            certificate = decoder.decode(der_content,
                                         asn1Spec=rfc2459.Certificate())[0]
            return X509Certificate(certificate)
        except Exception:
            raise X509CertificateError("Could not read X509 certificate from "
                                       "PEM data.")

    @staticmethod
    def from_buffer(data):
        """Build this X509 object from a data buffer in memory.

        :param data: A data buffer
        """
        return X509Certificate.from_open_file(io.StringIO(data))

    @staticmethod
    def from_file(path):
        """Build this X509 certificate object from a data file on disk.

        :param path: A data buffer
        """
        with open(path, 'r') as f:
            return X509Certificate.from_open_file(f)

    def as_pem(self):
        """Serialise this X509 certificate object as PEM string."""

        header = '-----BEGIN CERTIFICATE-----'
        footer = '-----END CERTIFICATE-----'
        der_cert = encoder.encode(self._cert)
        b64_encoder = (base64.encodestring if str is bytes else
                       base64.encodebytes)
        b64_cert = b64_encoder(der_cert).decode('ascii')
        return "%s\n%s%s\n" % (header, b64_cert, footer)

    def set_version(self, v):
        """Set the version of this X509 certificate object.

        :param v: The version
        """
        self._cert['tbsCertificate']['version'] = v

    def get_version(self):
        """Get the version of this X509 certificate object."""
        return self._cert['tbsCertificate']['version']

    def get_validity(self):
        if self._cert['tbsCertificate']['validity'] is None:
            self._cert['tbsCertificate']['validity'] = None
        return self._cert['tbsCertificate']['validity']

    def set_not_before(self, t):
        """Set the 'not before' date field.

        :param t: time in seconds since the epoch
        """
        asn1_time = utils.timestamp_to_asn1_time(t)
        validity = self.get_validity()
        validity['notBefore'] = asn1_time

    def get_not_before(self):
        """Get the 'not before' date field as seconds since the epoch."""
        validity = self.get_validity()
        not_before = validity['notBefore']
        return utils.asn1_time_to_timestamp(not_before)

    def set_not_after(self, t):
        """Set the 'not after' date field.

        :param t: time in seconds since the epoch
        """
        asn1_time = utils.timestamp_to_asn1_time(t)
        validity = self.get_validity()
        validity['notAfter'] = asn1_time

    def get_not_after(self):
        """Get the 'not after' date field as seconds since the epoch."""
        validity = self.get_validity()
        not_after = validity['notAfter']
        return utils.asn1_time_to_timestamp(not_after)

    def set_pubkey(self, pkey):
        """Set the public key field.

        :param pkey: The public key, rfc2459.SubjectPublicKeyInfo description
        """
        self._cert['tbsCertificate']['subjectPublicKeyInfo'] = pkey

    def get_subject(self):
        """Get the subject name field value.

        :return: An X509Name object instance
        """
        val = self._cert['tbsCertificate']['subject'][0]
        return name.X509Name(val)

    def set_subject(self, subject):
        """Set the subject name filed value.

        :param subject: An X509Name object instance
        """
        val = subject._name_obj
        if self._cert['tbsCertificate']['subject'] is None:
            self._cert['tbsCertificate']['subject'] = rfc2459.Name()
        self._cert['tbsCertificate']['subject'][0] = val

    def set_issuer(self, issuer):
        """Set the issuer name field value.

        :param issuer: An X509Name object instance
        """
        val = issuer._name_obj
        if self._cert['tbsCertificate']['issuer'] is None:
            self._cert['tbsCertificate']['issuer'] = rfc2459.Name()
        self._cert['tbsCertificate']['issuer'][0] = val

    def get_issuer(self):
        """Get the issuer name field value.

        :return: An X509Name object instance
        """
        val = self._cert['tbsCertificate']['issuer'][0]
        return name.X509Name(val)

    def set_serial_number(self, serial):
        """Set the serial number

        The serial number is a 32 bit integer value that should be unique to
        each certificate issued by a given certificate authority.

        :param serial: The serial number, 32 bit integer
        """
        self._cert['tbsCertificate']['serialNumber'] = serial

    def _get_extensions(self):
        if self._cert['tbsCertificate']['extensions'] is None:
            # this actually initialises the extensions tag rather than
            # assign None
            self._cert['tbsCertificate']['extensions'] = None
        return self._cert['tbsCertificate']['extensions']

    def get_extensions(self):
        extensions = self._get_extensions()
        return [extension.construct_extension(e) for e in extensions]

    def add_extension(self, ext, index):
        """Add an X509 V3 Certificate extension.

        :param ext: An X509Extension instance
        :param index: The index of the extension
        """
        if not isinstance(ext, extension.X509Extension):
            raise errors.X509Error("ext needs to be a pyasn1 extension")

        extensions = self._get_extensions()
        extensions[index] = ext.as_asn1()

    def sign(self, key, md='sha1'):
        """Sign the X509 certificate with a key using a message digest algorithm

        :param key: The signing key, an EVP_PKEY OpenSSL object
        :param md: The name of a message digest algorithm to use, it must be
                   valid and known to OpenSSL, possible values are
                   - md5
                   - sha1
                   - sha256
        """
        md = md.upper()

        if isinstance(key, rsa.RSAPrivateKey):
            encryption = 'RSA'
        elif isinstance(key, dsa.DSAPrivateKey):
            encryption = 'DSA'
        else:
            raise errors.X509Error("Unknown key type: %s" % (key.__class__,))

        hash_class = utils.get_hash_class(md)
        signature_type = SIGNING_ALGORITHMS.get((encryption, md))
        if signature_type is None:
            raise errors.X509Error(
                "Unknown encryption/hash combination %s/%s" % (encryption, md))

        algo_id = rfc2459.AlgorithmIdentifier()
        algo_id['algorithm'] = signature_type
        if encryption == 'RSA':
            algo_id['parameters'] = encoder.encode(asn1_univ.Null())
        elif encryption == 'DSA':
            pass  # parameters should be omitted, see RFC3279

        self._cert['tbsCertificate']['signature'] = algo_id

        to_sign = encoder.encode(self._cert['tbsCertificate'])
        if encryption == 'RSA':
            signer = key.signer(padding.PKCS1v15(), hash_class())
        elif encryption == 'DSA':
            signer = key.signer(hash_class())
        signer.update(to_sign)
        signature = signer.finalize()
        self._cert['signatureValue'] = "'%s'B" % (
            utils.bytes_to_bin(signature),)
        self._cert['signatureAlgorithm'] = algo_id

    def as_der(self):
        """Return this X509 certificate as DER encoded data."""
        return encoder.encode(self._cert)

    def get_fingerprint(self, md='md5'):
        """Get the fingerprint of this X509 certificate.

        :param md: The message digest algorthim used to compute the fingerprint
        :return: The fingerprint encoded as a hex string
        """
        hash_class = utils.get_hash_class(md)
        if hash_class is None:
            raise errors.X509Error(
                "Unknown hash %s" % (md,))
        hasher = hashes.Hash(hash_class(),
                             backend=cio_backends.default_backend())
        hasher.update(self.as_der())
        return binascii.hexlify(hasher.finalize()).upper().decode('ascii')
