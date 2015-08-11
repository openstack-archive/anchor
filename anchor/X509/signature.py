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

from cryptography import exceptions as cio_exceptions
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import encoder
from pyasn1.type import univ as asn1_univ
from pyasn1_modules import rfc2459

from anchor.X509 import errors


LOG = logging.getLogger(__name__)


sha224WithRSAEncryption = asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.14')
sha256WithRSAEncryption = asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.11')
sha384WithRSAEncryption = asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.12')
sha512WithRSAEncryption = asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.13')
id_dsa_with_sha224 = asn1_univ.ObjectIdentifier('2.16.840.1.101.3.4.3.1')
id_dsa_with_sha256 = asn1_univ.ObjectIdentifier('2.16.840.1.101.3.4.3.2')

SIGNING_ALGORITHMS = {
    ('RSA', 'MD5'): rfc2459.md5WithRSAEncryption,
    ('RSA', 'SHA1'): rfc2459.sha1WithRSAEncryption,
    ('RSA', 'SHA224'): sha224WithRSAEncryption,
    ('RSA', 'SHA256'): sha256WithRSAEncryption,
    ('RSA', 'SHA384'): sha384WithRSAEncryption,
    ('RSA', 'SHA512'): sha512WithRSAEncryption,
    ('DSA', 'SHA1'): rfc2459.id_dsa_with_sha1,
    ('DSA', 'SHA224'): id_dsa_with_sha224,
    ('DSA', 'SHA256'): id_dsa_with_sha256,
}


SIGNING_ALGORITHMS_INV = dict((v, k) for k, v in SIGNING_ALGORITHMS.items())


SIGNER_CONSTRUCTION = {
    rfc2459.md5WithRSAEncryption: (lambda key: key.signer(padding.PKCS1v15(),
                                                          hashes.MD5())),
    rfc2459.sha1WithRSAEncryption: (lambda key: key.signer(padding.PKCS1v15(),
                                                           hashes.SHA1())),
    sha224WithRSAEncryption: (lambda key: key.signer(padding.PKCS1v15(),
                                                     hashes.SHA224())),
    sha256WithRSAEncryption: (lambda key: key.signer(padding.PKCS1v15(),
                                                     hashes.SHA256())),
    sha384WithRSAEncryption: (lambda key: key.signer(padding.PKCS1v15(),
                                                     hashes.SHA384())),
    sha512WithRSAEncryption: (lambda key: key.signer(padding.PKCS1v15(),
                                                     hashes.SHA512())),
    rfc2459.id_dsa_with_sha1: (lambda key: key.signer(hashes.SHA1())),
    id_dsa_with_sha224: (lambda key: key.signer(hashes.SHA224())),
    id_dsa_with_sha256: (lambda key: key.signer(hashes.SHA256())),
}


VERIFIER_CONSTRUCTION = {
    rfc2459.md5WithRSAEncryption: (lambda key, signature: key.verifier(
        signature, padding.PKCS1v15(), hashes.MD5())),
    rfc2459.sha1WithRSAEncryption: (lambda key, signature: key.verifier(
        signature, padding.PKCS1v15(), hashes.SHA1())),
    sha224WithRSAEncryption: (lambda key, signature: key.verifier(
        signature, padding.PKCS1v15(), hashes.SHA224())),
    sha256WithRSAEncryption: (lambda key, signature: key.verifier(
        signature, padding.PKCS1v15(), hashes.SHA256())),
    sha384WithRSAEncryption: (lambda key, signature: key.verifier(
        signature, padding.PKCS1v15(), hashes.SHA384())),
    sha512WithRSAEncryption: (lambda key, signature: key.verifier(
        signature, padding.PKCS1v15(), hashes.SHA512())),
    rfc2459.id_dsa_with_sha1: (lambda key, signature: key.verifier(
        signature, hashes.SHA1())),
    id_dsa_with_sha224: (lambda key, signature: key.verifier(
        signature, hashes.SHA224())),
    id_dsa_with_sha256: (lambda key, signature: key.verifier(
        signature, hashes.SHA256())),
}


ALGORITHM_PARAMETERS = {
    rfc2459.md5WithRSAEncryption: encoder.encode(asn1_univ.Null()),
    rfc2459.sha1WithRSAEncryption: encoder.encode(asn1_univ.Null()),
    sha224WithRSAEncryption: encoder.encode(asn1_univ.Null()),
    sha256WithRSAEncryption: encoder.encode(asn1_univ.Null()),
    sha384WithRSAEncryption: encoder.encode(asn1_univ.Null()),
    sha512WithRSAEncryption: encoder.encode(asn1_univ.Null()),
    rfc2459.id_dsa_with_sha1: None,
    id_dsa_with_sha224: None,
    id_dsa_with_sha256: None,
}


class SignatureMixin(object):
    """Provides the sign() and verify() functions.

    Both operations rely on the functions provided by the certificate and
    csr classes.
    """
    def sign(self, key, md="sha1"):
        """Sign the current object."""
        md = md.upper()
        if key is None:
            raise errors.X509Error("Key required")

        if isinstance(key, rsa.RSAPrivateKey):
            encryption = 'RSA'
        elif isinstance(key, dsa.DSAPrivateKey):
            encryption = 'DSA'
        else:
            raise errors.X509Error("Unknown key type: %s" % (key.__class__,))

        signature_type = SIGNING_ALGORITHMS.get((encryption, md))
        if signature_type is None:
            raise errors.X509Error(
                "Unknown encryption/hash combination %s/%s" % (encryption, md))

        algo_id = rfc2459.AlgorithmIdentifier()
        algo_id['algorithm'] = signature_type
        algo_params = ALGORITHM_PARAMETERS[signature_type]
        if algo_params is not None:
            algo_id['parameters'] = algo_params

        self._embed_signature_algorithm(algo_id)
        to_sign = self._get_bytes_to_sign()
        signer = SIGNER_CONSTRUCTION[signature_type](key)
        signer.update(to_sign)
        signature = signer.finalize()

        self._embed_signature(algo_id, signature)

    def verify(self, key=None):
        algo_id = self._get_signing_algorithm()
        if algo_id not in SIGNING_ALGORITHMS_INV:
            LOG.warning("Signature algorithm %s is unknown, cannot verify",
                        algo_id)
            return False

        if key is None:
            key = self._get_public_key()

        encryption, hash_algo = SIGNING_ALGORITHMS_INV[algo_id]
        to_sign = self._get_bytes_to_sign()
        signature = self._get_signature()
        if ((encryption == 'RSA' and not isinstance(key, rsa.RSAPublicKey)) or
                (encryption == 'DSA' and not isinstance(key,
                                                        dsa.DSAPublicKey))):
            raise errors.X509Error("Key type mismatch: object %s, key %s" %
                                   (encryption, key.__class__))
        verifier = VERIFIER_CONSTRUCTION[algo_id](key, signature)

        verifier.update(to_sign)
        try:
            verifier.verify()
            return True
        except cio_exceptions.InvalidSignature:
            return False

    def _get_bytes_to_sign(self):
        """Get bytes which are giong to be hashed and signed."""
        raise NotImplementedError()

    def _get_public_key(self):
        """Get public key for verifying CSR self-signatures."""
        raise NotImplementedError()

    def _get_signature(self):
        """Get the current signature value as bytes."""
        raise NotImplementedError()

    def _get_signing_algorithm(self):
        """Get the description of algorithm used to sign object."""
        raise NotImplementedError()

    def _embed_signature_algorithm(self, algo_id):
        """Called before the signature is calculated.

        Since signature of the certificate depends on the signature algorithm,
        it needs to be saved first.
        """
        raise NotImplementedError()

    def _embed_signature(self, algo_id, signature):
        """Called after the signature is calculated."""
        raise NotImplementedError()
