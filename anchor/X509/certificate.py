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

import io

from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import univ as asn1_univ
from pyasn1.type import tag as asn1_tag
from pyasn1_modules import pem
from pyasn1_modules import rfc2459  # X509v3
from Crypto.Hash import hashalgo
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

from anchor.X509 import errors
from anchor.X509 import name
from anchor.X509 import utils


SIGNING_ALGORITHMS = {
    ('RSA', 'MD5'): rfc2459.md5WithRSAEncryption,
    ('RSA', 'SHA'): rfc2459.sha1WithRSAEncryption,
    ('RSA', 'SHA224'): asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.14'),
    ('RSA', 'SHA256'): asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.11'),
    ('RSA', 'SHA384'): asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.12'),
    ('RSA', 'SHA512'): asn1_univ.ObjectIdentifier('1.2.840.113549.1.1.13'),
}


EXTENSION_NAMES = {
    rfc2459.id_ce_policyConstraints: 'policyConstraints',
    rfc2459.id_ce_basicConstraints: 'basicConstraints',
    rfc2459.id_ce_subjectDirectoryAttributes: 'subjectDirectoryAttributes',
    rfc2459.id_ce_deltaCRLIndicator: 'deltaCRLIndicator',
    rfc2459.id_ce_cRLDistributionPoints: 'cRLDistributionPoints',
    rfc2459.id_ce_issuingDistributionPoint: 'issuingDistributionPoint',
    rfc2459.id_ce_nameConstraints: 'nameConstraints',
    rfc2459.id_ce_certificatePolicies: 'certificatePolicies',
    rfc2459.id_ce_policyMappings: 'policyMappings',
    rfc2459.id_ce_privateKeyUsagePeriod: 'privateKeyUsagePeriod',
    rfc2459.id_ce_keyUsage: 'keyUsage',
    rfc2459.id_ce_authorityKeyIdentifier: 'authorityKeyIdentifier',
    rfc2459.id_ce_subjectKeyIdentifier: 'subjectKeyIdentifier',
    rfc2459.id_ce_certificateIssuer: 'certificateIssuer',
    rfc2459.id_ce_subjectAltName: 'subjectAltName',
    rfc2459.id_ce_issuerAltName: 'issuerAltName',
}


class X509CertificateError(errors.X509Error):
    """Specific error for X509 certificate operations."""
    pass


class X509ExtensionValue(object):
    def __init__(self, ext_der=None):
        if ext_der:
            self._ext = decoder.decode(ext_der, self.spec())[0]
        else:
            self._ext = self.spec()


class X509ExtensionBasicConstraints(X509ExtensionValue):
    oid = rfc2459.id_ce_basicConstraints
    spec = rfc2459.BasicConstraints

    def get_ca(self):
        return bool(self._ext['cA'])

    def set_ca(self, ca):
        self._ext['cA'] = ca

    def get_path_len_constraint(self):
        return self._ext['pathLenConstraint']

    def set_path_len_constraint(self, length):
        self._ext['pathLenConstraint'] = length

    def __str__(self):
        return "CA: %s, pathLen: %i" % (self.get_ca(), self.get_path_len_constraint())


EXTENSION_CLASSES = {
    rfc2459.id_ce_basicConstraints: X509ExtensionBasicConstraints,
}


class X509Extension(object):
    """An X509 V3 Certificate extension."""
    def __init__(self, ext):
        if not isinstance(ext, rfc2459.Extension):
            raise errors.X509Error("extension has incorrect type")
        self._ext = ext

    def __str__(self):
        return "%s %s" % (self.get_name(), self.get_value())

    def get_oid(self):
        return self._ext['extnID']

    def get_name(self):
        """Get the extension name as a python string."""
        oid = self.get_oid()
        return EXTENSION_NAMES.get(oid, oid)

    def get_value(self):
        """Get the extension value as a python string."""
        oid = self.get_oid()
        value = self._ext['extnValue']
        #if oid in EXTENSION_CLASSES:
        #    return EXTENSION_CLASSES[oid](value)
        #else:
        return value


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
            certificate = decoder.decode(der_content, asn1Spec=rfc2459.Certificate())[0]
            return X509Certificate(certificate)
        except Exception:
            raise X509CertificateError("Could not read X509 certificate from "
                                       "PEM data.")

    @staticmethod
    def from_buffer(data):
        """Build this X509 object from a data buffer in memory.

        :param data: A data buffer
        """
        
        return X509Certificate.from_open_file(io.BytesIO(data))

    @staticmethod
    def from_file(path):
        """Build this X509 certificate object from a data file on disk.

        :param path: A data buffer
        """
        with open(path, 'rb') as f:
            return X509Certificate.from_open_file(f)

    def as_pem(self):
        """Serialise this X509 certificate object as PEM string."""

        header = '-----BEGIN CERTIFICATE-----'
        footer = '-----END CERTIFICATE-----'
        der_cert = encoder.encode(self._cert)
        b64_cert = pem.base64.encodestring(der_cert)
        return "%s\n%s%s\n" % (header, b64_cert, footer)

    def set_version(self, v):
        """Set the version of this X509 certificate object.

        :param v: The version
        """
        self._cert['tbsCertificate']['version'] = v

    def get_version(self):
        """Get the version of this X509 certificate object."""
        return self._cert['tbsCertificate']['version']

    def set_not_before(self, t):
        """Set the 'not before' date field.

        :param t: time in seconds since the epoch
        """
        asn1_time = utils.timestamp_to_asn1_time(t)
        if self._cert['tbsCertificate']['validity'] is None:
            self._cert['tbsCertificate']['validity'] = rfc2459.Validity()
        self._cert['tbsCertificate']['validity']['notBefore'] = asn1_time

    def get_not_before(self):
        """Get the 'not before' date field as seconds since the epoch."""
        not_before = self._cert['tbsCertificate']['validity']['notBefore']
        return utils.asn1_time_to_timestamp(not_before)

    def set_not_after(self, t):
        """Set the 'not after' date field.

        :param t: time in seconds since the epoch
        """
        asn1_time = utils.timestamp_to_asn1_time(t)
        if self._cert['tbsCertificate']['validity'] is None:
            self._cert['tbsCertificate']['validity'] = rfc2459.Validity()
        self._cert['tbsCertificate']['validity']['notAfter'] = asn1_time

    def get_not_after(self):
        """Get the 'not after' date field as seconds since the epoch."""
        not_after = self._cert['tbsCertificate']['validity']['notAfter']
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

    def add_extension(self, ext, index):
        """Add an X509 V3 Certificate extension.

        :param ext: An X509Extension instance
        :param index: The index of the extension
        """
        if not isinstance(ext, X509Extension):
            raise AttributeError("ext needs to be a pyasn1 extension")

        if self._cert['tbsCertificate']['extensions'] is None:
            self._cert['tbsCertificate']['extensions'] = rfc2459.Extensions().subtype(explicitTag=asn1_tag.Tag(asn1_tag.tagClassContext, asn1_tag.tagFormatSimple, 3))
        self._cert['tbsCertificate']['extensions'][index] = ext._ext

    def sign(self, key, md='sha1'):
        """Sign the X509 certificate with a key using a message digest algorithm

        :param key: The signing key, an EVP_PKEY OpenSSL object
        :param md: The name of a message digest algorithm to use, it must be
                   valid and known to OpenSSL, possible values are
                   - md5
                   - sha1
                   - sha256
        """
        if hasattr(key, 'implementation') and isinstance(key.implementation, RSA.RSAImplementation):
            encryption = 'RSA'
        else:
            raise errors.X509Error("Unknown key type: %s" % (key,))

        md, hash_module = utils.get_hash_module(md)
        algo_id = rfc2459.AlgorithmIdentifier()
        algo_id['algorithm'] = SIGNING_ALGORITHMS[(encryption, md)]
        algo_id['parameters'] = encoder.encode(asn1_univ.Null())

        self._cert['tbsCertificate']['signature'] = algo_id

        to_sign = encoder.encode(self._cert['tbsCertificate'])
        hash_to_sign = hashalgo.HashAlgo(hash_module, to_sign)
        setattr(hash_to_sign, "oid", hash_to_sign._hash.oid)
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(hash_to_sign)
        self._cert['signatureValue'] = "'%s'B" % (utils.bytes_to_bin(signature),)
        self._cert['signatureAlgorithm'] = algo_id

    def as_der(self):
        """Return this X509 certificate as DER encoded data."""
        return encoder.encode(self._cert)

    def get_fingerprint(self, md='md5'):
        """Get the fingerprint of this X509 certificate.

        :param md: The message digest algorthim used to compute the fingerprint
        :return: The fingerprint encoded as a hex string
        """
        _, hash_module = utils.get_hash_module(md)
        digest = hashalgo.HashAlgo(hash_module, self.as_der()).hexdigest()
        return digest.upper()
