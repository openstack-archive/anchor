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
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import univ as asn1_univ
from pyasn1_modules import pem

from anchor.asn1 import rfc5280
from anchor.X509 import errors
from anchor.X509 import extension
from anchor.X509 import name
from anchor.X509 import signature
from anchor.X509 import utils


SIGNING_ALGORITHMS = {
    ('RSA', 'SHA224'): asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.14'),
    ('RSA', 'SHA256'): asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.11'),
    ('RSA', 'SHA384'): asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.12'),
    ('RSA', 'SHA512'): asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.13'),
    ('DSA', 'SHA224'): asn1_univ.ObjectIdentifier('2.16.840.1.101.3.4.3.1'),
    ('DSA', 'SHA256'): asn1_univ.ObjectIdentifier('2.16.840.1.101.3.4.3.2'),
}


SIGNING_ALGORITHMS_INV = dict((v, k) for k, v in SIGNING_ALGORITHMS.items())


class X509CertificateError(errors.X509Error):
    """Specific error for X509 certificate operations."""
    pass


class X509Certificate(signature.SignatureMixin):
    """X509 certificate class."""
    def __init__(self, certificate=None):
        if certificate is None:
            self._cert = rfc5280.Certificate()
            self._cert['tbsCertificate'] = rfc5280.TBSCertificate()
        else:
            self._cert = certificate

    @staticmethod
    def from_open_file(f):
        try:
            der_content = pem.readPemFromFile(f)
            certificate = decoder.decode(der_content,
                                         asn1Spec=rfc5280.Certificate())[0]
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

        :param pkey: The public key, rfc5280.SubjectPublicKeyInfo description
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
            self._cert['tbsCertificate']['subject'] = rfc5280.Name()
        self._cert['tbsCertificate']['subject'][0] = val

    def set_issuer(self, issuer):
        """Set the issuer name field value.

        :param issuer: An X509Name object instance
        """
        val = issuer._name_obj
        if self._cert['tbsCertificate']['issuer'] is None:
            self._cert['tbsCertificate']['issuer'] = rfc5280.Name()
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

    def get_serial_number(self,):
        return self._cert['tbsCertificate']['serialNumber']

    def _get_extensions(self):
        if self._cert['tbsCertificate']['extensions'] is None:
            # this actually initialises the extensions tag rather than
            # assign None
            self._cert['tbsCertificate']['extensions'] = None
        return self._cert['tbsCertificate']['extensions']

    def get_extensions(self, ext_type=None):
        extensions = self._get_extensions()
        return [extension.construct_extension(e) for e in extensions
                if ext_type is None or e['extnID'] == ext_type._oid]

    def add_extension(self, ext, index):
        """Add an X509 V3 Certificate extension.

        :param ext: An X509Extension instance
        :param index: The index of the extension
        """
        if not isinstance(ext, extension.X509Extension):
            raise errors.X509Error("ext needs to be a pyasn1 extension")

        extensions = self._get_extensions()
        extensions[index] = ext.as_asn1()

    def _get_bytes_to_sign(self):
        return encoder.encode(self._cert['tbsCertificate'])

    def _embed_signature_algorithm(self, algo_id):
        self._cert['tbsCertificate']['signature'] = algo_id

    def _embed_signature(self, algo_id, signature):
        self._cert['signature'] = "'%s'H" % (
            str(binascii.hexlify(signature).decode('ascii')),)
        self._cert['signatureAlgorithm'] = algo_id

    def _get_signature(self):
        return utils.bin_to_bytes(self._cert['signature'])

    def _get_signing_algorithm(self):
        tbs_signature = self._cert['tbsCertificate']['signature']
        cert_signature = self._cert['signatureAlgorithm']
        if tbs_signature != cert_signature:
            raise errors.X509Error("algorithms mismatch")

        return tbs_signature['algorithm']

    def as_der(self):
        """Return this X509 certificate as DER encoded data."""
        return encoder.encode(self._cert)

    def get_fingerprint(self, md='sha256'):
        """Get the fingerprint of this X509 certificate.

        :param md: The message digest algorithm used to compute the fingerprint
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

    def get_key_id(self):
        """Construct a key identifier from public key.

        Return the hash useful for keyIdentifier field, constructed as
        described in RFC5280 section 4.2.1.2, method 1. The result is
        SHA1(subjectPublicKey).
        """
        key_info = self._cert['tbsCertificate']['subjectPublicKeyInfo']
        public_key = key_info['subjectPublicKey']
        # get the actual bit string value, without the length and tags
        value = ber_encoder.BitStringEncoder().encodeValue(
            None, public_key, True, None)[0][1:]
        digest = hashes.Hash(hashes.SHA1(),
                             backend=cio_backends.default_backend())
        digest.update(value)
        return digest.finalize()
