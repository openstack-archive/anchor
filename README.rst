Anchor
======

.. image:: https://img.shields.io/pypi/v/anchor.svg
    :target: https://pypi.python.org/pypi/anchor/
    :alt: Latest Version

.. image:: https://img.shields.io/pypi/pyversions/anchor.svg
    :target: https://pypi.python.org/pypi/anchor/
    :alt: Python Versions

.. image:: https://img.shields.io/pypi/format/anchor.svg
    :target: https://pypi.python.org/pypi/anchor/
    :alt: Format

.. image:: https://img.shields.io/badge/license-Apache%202-blue.svg
    :target: https://git.openstack.org/cgit/openstack/anchor/plain/LICENSE
    :alt: License

Anchor is an ephemeral PKI service that, based on certain conditions,
automates the verification of CSRs and signs certificates for clients.
The validity period can be set in the config file with hour resolution.

Ideas behind Anchor
===================

A critical capability within PKI is to revoke a certificate - to ensure
that it is no longer trusted by any peer. Unfortunately research has
demonstrated that the two typical methods of revocation (Certificate
Revocation Lists and Online Certificate Status Protocol) both have
failings that make them unreliable, especially when attempting to
leverage PKI outside of web-browser software.

Through the use of short-lifetime certificates Anchor introduces the
concept of "passive revocation". By issuing certificates with lifetimes
measured in hours, revocation can be achieved by simply not re-issuing
certificates to clients.

The benefits of using Anchor instead of manual long-term certificates
are:

* quick certificate revoking / rotation
* always tested certificate update mechanism (used daily)
* easy integration with certmonger for service restarting
* certificates are signed only when validation is passed
* signing certificates follows consistent process

Installation
============

In order to install Anchor from source, the following system
dependencies need to be present:

* python 2.7
* python (dev files)
* libffi (dev)
* libssl (dev)

When everything is in place, Anchor can be installed in one of three
ways: a local development instance in a python virtual environment, a local
production instance or a test instance in a docker container.

For a development instance with virtualenv, run:

    virtualenv .venv && source .venv/bin/activate && pip install .

For installing in production, either install a perpared system package,
or install globally in the system:

    python setup.py install

Running the service
===================

In order to run the service, it needs to be started via the `pecan`
application server. The only extra parameter is a config file:

    pecan serve config.py

For development, an additional `--reload` parameter may be used. It will
cause the service to reload every time a source file is changed, however
it requires installing an additional `watchdog` python module.

In the default configuration, Anchor will wait for web requests on port
5016 on local network interface. This can be adjusted in the `config.py`
file.

Preparing a test environment
============================

In order to test Anchor with the default configuration, the following
can be done to create a test CA. The test certificate can be then used
to sign the new certificates.

    openssl req -out CA/root-ca.crt -keyout CA/root-ca-unwrapped.key \
        -newkey rsa:4096 -subj "/CN=Anchor Test CA" -nodes -x509 -days 365
    chmod 0400 CA/root-ca-unwrapped.key

Next, a new certificate request may be generated:

    openssl req -out anchor-test.example.com.csr -nodes \
        -keyout anchor-test.example.com.key -newkey rsa:2048 \
        -subj "/CN=anchor-test.example.com"

That reqest can be submitted using curl (while `pecan serve config.py`
is running):

    curl http://0.0.0.0:5016/v1/sign/default -F user='myusername' \
        -F secret='simplepassword' -F encoding=pem \
        -F 'csr=<anchor-test.example.com.csr'

This will result in the signed request being created in the `certs`
directory.

Docker test environment
=======================
We have provided a Dockerfile that can be used to build a container that
will run anchor

These instructions expect the reader to have a working Docker install
already. Docker should *not* be used to serve Anchor in any production
environments.

Assuming you are already in the anchor directory, build a container
called 'anchor' that runs the anchor service, with any local changes
that have been made in the repo:

    docker build -t anchor .

To start the service in the container and serve Anchor on port 5016:

    docker run -p 5016:5016 anchor

The anchor application should be accessible on port 5016. If you are
running docker natively on Linux, that will be 5016 on localhost
(127.0.0.1). If you are running docker under Microsoft Windows or Apple
OSX it will be running in a docker machine. To find the docker machine
IP address run:

    docker-machine ip default

Running Anchor in production
============================

Anchor shouldn't be exposed directly to the network. It's running via an
application server (Pecan) and doesn't have all the features you'd
normally expect from a http proxy - for example dealing well with
deliberately slow connections, or using multiple workers. Anchor can
however be run in production using a better frontend.

To run Anchor using uwsgi you can use the following command:

    uwsgi --http-socket :5016 --venv path/to/venv --pecan config.py -p 4

In case a more complex scripted configuration is needed, for example to
handle custom headers, rate limiting, or source filtering a complete
HTTP proxy like Nginx may be needed. This is however out of scope for
Anchor project. You can read more about production deployment in
[Pecan documentation](http://pecan.readthedocs.org/en/latest/deployment.html).

Additionally, using an AppArmor profile for Anchor is a good idea to
prevent exploits relying on one of the native libraries used by Anchor
(for example OpenSSL). This can be done with sample profiles which you
can find in the `tools/apparmor.anchor_*` files. The used file needs to
be reviewed and updated with the right paths depending on the deployment
location.

Validators
==========

One of the main features of Anchor are the validators which make sure
that all requests match a given set of rules. They're configured in
`config.json` and the sample configuration includes a few of them.

Each validator takes a dictionary of options which provide the specific
matching conditions.

Currently available validators are:

* `common_name` ensures CN matches one of names in `allowed_domains` or
ranges in `allowed_networks`

* `alternative_names` ensures alternative names match one of the names
in `allowed_domains`

* `alternative_names_ip` ensures alternative names match one of the
names in `allowed_domains` or IP ranges in `allowed_networks`

* `blacklist_names` ensures CN and alternative names do not contain any
of the configured `domains`

* `server_group` ensures the group the requester is contained within
  `group_prefixes`

* `extensions` ensures only `allowed_extensions` are present in the
request

* `key_usage` ensures only `allowed_usage` is requested for the
certificate

* `ca_status` ensures the request does/doesn't require the CA flag

* `source_cidrs` ensures the request comes from one of the ranges in
`cidrs`

A configuration entry for a validator might look like one from the
sample config:

    "key_usage": {
      "allowed_usage": [
        "Digital Signature",
        "Key Encipherment",
        "Non Repudiation"
      ]
    }

Authentication
==============

Anchor can use one of the following authentication modules: static,
keystone, ldap.

Static: Username and password are present in `config.json`. This mode
should be used only for development and testing.

  "auth": {
    "static": {
      "secret": "simplepassword",
      "user": "myusername"
    }
  }

Keystone: Username is ignored, but password is a token valid in the
configured keystone location.

  "auth": {
    "keystone": {
      "url": "https://keystone.example.com"
    }
  }

LDAP: Username and password are used to bind to an LDAP user in a
configured domain. User's groups for the `server_group` filter are
retrieved from attribute `memberOf` in search for
`(sAMAccountName=username@domain)`. The search is done in the configured
base.

    "auth": {
      "ldap": {
        "host": "ldap.example.com",
        "base": "ou=Users,dc=example,dc=com",
        "domain": "example.com"
        "port": 636,
        "ssl": true
      }
    }

Signing backends
================

Anchor allows the use of configurable signing backend. Currently it provides two
implementation: one based on cryptography.io ("anchor"), the other using PKCS#11
libraries ("pkcs11"). The first one is used in the sample config. Other backends
may have extra dependencies: pkcs11 requires the PyKCS11 module, not required by
anchor by default.

The resulting certificate is stored locally if the `output_path` is set
to any string. This does not depend on the configured backend.

Backends can specify their own options - please refer to the backend
documentation for the specific list. The default backend takes the
following options:

* `cert_path`: path where local CA certificate can be found

* `key_path`: path to the key for that certificate

* `signing_hash`: which hash method to use when producing signatures

* `valid_hours`: number of hours the signed certificates are valid for

Sample configuration for the default backend:

    "ca": {
      "backend": "anchor"
      "cert_path": "CA/root-ca.crt",
      "key_path": "CA/root-ca-unwrapped.key",
      "output_path": "certs",
      "signing_hash": "sha256",
      "valid_hours": 24
    }

Other backends may be created too. For more information, please refer to the
documentation.

Fixups
======

Anchor can modify the submitted CSRs in order to enforce some rules,
remove deprecated elements, or just add information. Submitted CSR may
be modified or entirely redone. Fixup are loaded from "anchor.fixups"
namespace and can take parameters just like validators.

Reporting bugs and contributing
===============================

For bug reporting and contributing, please check the CONTRIBUTING.rst
file.
