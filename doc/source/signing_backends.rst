Signing backends
================

Each signing backend must be registered using an entry point. They're loaded
using the ``stevedore`` module, however this should not affect the calling
behaviour.

The signing CA configuration block allows the following common options:

* ``backend``: name of the requested backend ("anchor" not defined)
* ``output_path``: local path where anchor saves the issued certificates
  (optional, output not saved if not defined)

Anchor provides the following backends out of the box:

anchor
------

The default signing backend. It doesn't have any external service dependencies
and all signing happens inside of the Anchor process.

This backend will ignore all non-critical extensions which are not understood
by Anchor and will reject CSRs with unknown critical extensions.

A sample configuration for the ``signing_ca`` block looks like this:

.. code:: json

  {
    "local": {
      "backend": "anchor",
      "cert_path": "CA/root-ca.crt",
      "key_path": "CA/root-ca-unwrapped.key",
      "output_path": "certs",
      "signing_hash": "sha256",
      "valid_hours": 24
    }
  }

Valid options for this backend are:

* ``cert_path``: path to the signing CA certificate
* ``key_path``: path to the matching key
* ``signing_hash``: hash to use when signing the issued certificate ("md5",
  "sha1", "sha224, "sha256" are valid options)
* ``valid_hours``: validity period for the issued certificates, defined in
  hours

pkcs11
------

This backend uses a provided pkcs11 library for the signing operation. The final
certificate is created in the same way as with `anchor` backend with regards to
extensions and fixups.

The interface doesn't rely on any special functionality of the store. Only the
RSA private key needs to be available as a secret. The only used mechanism is
CKM_RSA_PKCS. That means any pkcs11 backend from gnome keyring to tpm and
external HSMs should work.

This backend requires ``PyKCS11`` package to be installed.

A sample configuration for the ``signing_ca`` block looks like this:

.. code:: json

  {
    "local": {
      "backend": "pkcs11",
      "cert_path": "CA/root-ca.crt",
      "output_path": "certs",
      "signing_hash": "sha256",
      "valid_hours": 24,
	  "slot": 18,
	  "pin": "the_pin",
	  "key_id": "b22f6e84a7b29db389b57a24384b95cca0bb4bc0",
	  "pkcs11_path": "/usr/lib/.../pkcs11/...-pkcs11.so"
    }
  }

Valid options for this backend are:

* ``cert_path``: path to the signing CA certificate
* ``signing_hash``: hash to use when signing the issued certificate ("sha224,
  "sha256", "sha384", "sha512" are valid options)
* ``valid_hours``: validity period for the issued certificates, defined in
  hours
* ``slot``: slot number where the key can be found
* ``pin``: text version of the pin required to access the right slot
* ``key_id``: key id written as a hex string
* ``pkcs11_path``: path to the dynamic library compatible with pkcs11 interface

Backend development
-------------------

Backends are simple functions which need to take 2 parameters: the CSR in PEM
format and the configuration block contents. Configuration can contain any keys
required by the backend.

The return value must be a signed certificate in PEM format, however in most
cases it's enough to implement the actual hash signing part and rely on
``anchor.signer.sign_generic`` framework. The backend may either throw a
specific ``WebOb`` HTTP exception, or SigningError exception which will result
in a 500 response.

For security, http exceptions from the signing backend should not expose any
specific information about the reason for failure. Internal exceptions are
preferred for this reason and their details will be logged in Anchor.

The backend must not rely on the received CSR signature. If any modifications
are applied to the submitted CSR in Anchor, they will invalidate the signature.
Unless the backend is intended to work only with validators, and not any fixup
operations in the future, the signature field should be ignored and the request
treated as already correct/verified.

Configuration is verified using the function provided using the
``@signers.config_validator(f)`` decorator.
