Configuration files
===================

Anchor is configured using two files: ``config.py`` and ``config.json``. The
first one defines the Python and webservice related values. You can change the
listening iterface address and port there, as well as logging details to suit
your deployment. The second configuration defines the service behaviour at
runtime.

There are three main sections at the moment: ``authentication`` for
authentication parameters, ``signing_ca`` for defining signing authorities, and
``registration_authority`` for listing virtual registration authorities which
can be selected by client requests.

The main ``config.json`` structure looks like this:

.. code:: json

  {
    "authentication": { ... },
    "signing_ca": { ... },
    "registration_authority": { ... }
  }

Each block apart from ``registration_authority`` defines a number of mapping
from labels to definitions. Those labels can then be used in the
``registration_authority`` block to refer to settings defined earlier.

Authentication
--------------

The authentication block can define any number of authentication blocks, each
using one specific authentication backend.

Currently available authentication methods are: ``static``, ``keystone``, and
``ldap``.

Static
~~~~~~

Username and password are present in ``config.json``. This mode should be used
only for development and testing.

.. code:: json

  {
    "authentication": {
      "method_1": {
        "backend": "static",
        "secret": "simplepassword",
        "user": "myusername"
      }
    }
  }

Keystone
~~~~~~~~

Username is ignored, but password is a token valid in the configured keystone
location.

.. code:: json

  {
    "authentication": {
      "method_2": {
        "backend": "keystone",
        "url": "https://keystone.example.com"
      }
    }
  }

LDAP
~~~~

Username and password are used to bind to an LDAP user in a configured domain.
User's groups for the ``server_group`` filter are retrieved from attribute
``memberOf`` in search for ``(sAMAccountName=username@domain)``. The search is done
in the configured base.

.. code:: json

  {
    "authentication": {
      "method_3": {
        "backend": "ldap",
        "host": "ldap.example.com",
        "base": "ou=Users,dc=example,dc=com",
        "domain": "example.com",
        "port": 636,
        "ssl": true
      }
    }
  }


Signing authority
-----------------

The ``signing_ca`` section defines any number of signing authorities which can
be referenced later on. Currently there's only one, default implementation
which uses local files. An example configuration looks like this.

.. code:: json

  {
    "signing_ca": {
      "local": {
        "backend": "anchor",
        "cert_path": "CA/root-ca.crt",
        "key_path": "CA/root-ca-unwrapped.key",
        "output_path": "certs",
        "signing_hash": "sha256",
        "valid_hours": 24
      }
    }
  }

Anchor allows the use of configurable signing backend. While it provides a
default implementation (based on cryptography.io and OpenSSL), other
implementations may be configured. The backend is configured by setting the
``backend`` value to the name of the right entry point. Backend implementations
need to provide only one function: ``sign(csr, config)``, taking the parsed CSR
and their own ``singing_ca`` block of the configuration as parameters and
returning signed certificate in PEM format.

The backends are loaded using the ``stevedore`` module from the registered
entry points. The name space is ``anchor.signing_backends``.

Each backend may take different configuration options. Please refer to
:doc:`signing backends section </signing_backends>`.


Virtual registration authority
------------------------------

The registration authority section puts together previously described elements
and the list of validators applied to each request.

.. code:: json

  {
    "registration_authority": {
      "default": {
        "authentication": "method_1",
        "signing_ca": "local",
        "validators": {
          "ca_status": {
            "ca_requested": false
          },
          "source_cidrs": {
            "cidrs": [ "127.0.0.0/8" ]
          }
        },
        "fixups": {
        }
      }
    }
  }

In the example above, CSRs sent to registration authority ``default`` will be
authenticated using previously defined block ``method_1``, will be validated
against two validators (``ca_status`` and ``source_cidrs``) and if they pass,
the CSR will be signed by the previously defined signing ca called ``local``.

Each validator has its own set of parameters described separately in the
:doc:`validators section </validators>`. Same for fixups described in
:doc:`fixups section </fixups>`


Audit
-----

Audit has two possible targets: ``log`` for output in the standard logging
stream and ``messaging`` for the openstack message queue. The first one doesn't
require any extra options:

.. code:: json

  {
    "audit": {
      "target": "log"
    }
  }

The message queue version requires defining a target in a way compatible with
``oslo_messaging`` `transport URIs`_. For example:

.. code:: json

  {
    "audit": {
      "target": "messaging",
      "url": "rabbit:guest@localhost:5672"
    }
  }

Example configuration
---------------------

.. code:: json

  {
    "authentication": {
      "method_1": {
        "backend": "static",
        "secret": "simplepassword",
        "user": "myusername"
      }
    },

    "signing_ca": {
      "local": {
        "cert_path": "CA/root-ca.crt",
        "key_path": "CA/root-ca-unwrapped.key",
        "output_path": "certs",
        "signing_hash": "sha256",
        "valid_hours": 24
      }
    },

    "registration_authority": {
      "default": {
        "authentication": "method_1",
        "signing_ca": "local",
        "validators": {
          "ca_status": {
            "ca_requested": false
          },
          "source_cidrs": {
            "cidrs": [ "127.0.0.0/8" ]
          }
        },
        "fixups": {
        }
      }
    }
  }

.. _transport URIs: https://wiki.openstack.org/wiki/Oslo/Messaging#Transports
