Anchor
============

Anchor is an ephemeral PKI service that, based on certain conditions,
automates the verification of CSRs and signs certificates for clients.
The validity period can be set in the config file with hour resolution.

Ideas behind Anchor
===================

Usual CA behaviour is to generate and assign long-term certificates, typically
valid for months, or years. This results in a few issues. The most important is
that in case of compromise clients need to know the old certificate is invalid,
but CSRs are almost never used. Anchor uses a different approach, where
certificates are constantly rotated - typical grant time is expected to be for
24 hour period. This means a completely automated rotation can be achieved each
day.

The benefits of using Anchor instead of manual long-term certificates are:

* quick certificate revoking / rotation
* always tested certificate update mechanism (used daily)
* easy integration with certmonger for service restarting
* certificates are signed only when validation is passed
* signing certificates follows consistent process

Installation
============

In order to install Anchor from source, the following system dependencies need
to be present:

* python 2.7
* python (dev files)
* libffi (dev)
* libssl (dev)
* ldap (dev, optional)
* sasl (dev, optional)

When everything is in place, Anchor can be installed in one of three ways. For
development, run:

    virtualenv .venv
    . .venv/bin/activate
    python setup.py develop

For installing into virtualenv, run:

    virtualenv path/to/environment
    . path/to/environment/bin/activate
    python setup.py install

For installing in production, either install a perpared system package, or
install globally in the system:

    python setup.py install

Running the service
===================

In order to run the service, it needs to be started via `pecan` application
server. The only extra parameter is a config file:

    pecan serve config.py

For development, an additional `--reload` parameter may be used. It will cause
the service to reload every time a source file is changed, however it requires
installing an additional `watchdog` python module.

In the default configuration, Anchor will wait for web requests on port 5000 on
local network interface. This can be adjusted in the `config.py` file.

Preparing a test environment
============================

In order to test Anchor with the default configuration, the following can be
done to create a test CA. The test certificate can be then used to sign the new
certificates.

    openssl req -out CA/root-ca.crt -keyout CA/root-ca-unwrapped.key \
        -newkey rsa:4096 -subj "/CN=Anchor Test CA" -nodes -x509 -days 365
    chmod 0400 CA/root-ca-unwrapped.key

Next, a new certificate request may be generated:

    openssl req -out anchor-test.example.com.csr -nodes \
        -keyout anchor-test.example.com.key -newkey rsa:2048 \
        -subj "/CN=anchor-test.example.com"

That reqest can be submitted using curl (while `pecan serve config.py` is
running):

    curl http://0.0.0.0:5000/sign -F user='myusername' \
        -F secret='simplepassword' -F encoding=pem \
        -F 'csr=<anchor-test.example.com.csr'

This will result in the signed request being created in the `certs` directory.

Running Anchor in production
============================

Anchor shouldn't be exposed directly to the network. It's running via an
application server (Pecan) and doesn't have all the features you'd normally
expect from a http proxy - for example dealing well with deliberately slow
connections, or using multiple workers. Anchor can be however run in production
using a better frontend.

To run Anchor using uwsgi you can use the following command:

    uwsgi --http-socket :5000 --venv path/to/venv --pecan config.py -p 4

In case a more complex scripted configuration is needed, for example to handle
custom headers, rate limiting, or source filtering a complete HTTP proxy like
Nginx may be needed. This is however out of scope for Anchor project. You can
read more about production deployment in
[Pecan documentation](http://pecan.readthedocs.org/en/latest/deployment.html).

Additionally, using an AppArmor profile for Anchor is a good idea to prevent
exploits relying on one of the native libraries used by Anchor (for example
OpenSSL). This can be done with sample profiles which you can find in the
`tools/apparmor.anchor_*` files. The used file needs to be reviewed and updated
with the right paths depending on the deployment location.

Validators
==========

One of the main features of Anchor are the validators which make sure that all
requests match a given set of rules. They're configured in `config.json` and
the sample configuration includes a few of them.

Each validator takes dictionary of options which provide the specific matching
conditions.

Currenly available validators are:

* `common_name` ensures CN matches one of names in `allowed_domains` or ranges
  in `allowed_networks`

* `alternative_names` ensures alternative names match one of the names in
  `allowed_domains`

* `alternative_names_ip` ensures alternative names match one of the names in
  `allowed_domains` or ranges in `allowed_networks`

* `server_group` ensures the group the requester belongs to one of
  `group_prefixes`

* `extensions` ensures only `allowed_extensions` are present in the request

* `key_usage` ensures only `allowed_usage` is requested for the certificate

* `ca_status` ensures the request does/doesn't require the CA flag

* `source_cidrs` ensures the request comes from one of the ranges in `cidrs`

A configuration entry for a validator looks like this one from sample config:

    "key_usage": {
      "allowed_usage": [
        "Digital Signature",
        "Key Encipherment",
        "Non Repudiation"
      ]
    }

Authentication
==============

Anchor can use following authentication modules: static, keystone, ldap.

Static: Username and password are present in `config.json`. This mode should be
used only for development and testing.

  "auth": {
    "static": {
      "secret": "simplepassword",
      "user": "myusername"
    }
  }

Keystone: Username is ignored, but password is a token valid in the configured
keystone location.

  "auth": {
    "keystone": {
      "url": "https://keystone.example.com"
    }
  }

LDAP: Username and password are used to bind to an LDAP user in a configured
domain. User's groups for the `server_group` filter are retrieved from
attribute `memberOf` in search for `(sAMAccountName=username@domain)`. The
search is done in the configured base.

    "auth": {
      "ldap": {
        "host": "ldap.example.com",
        "base": "ou=Users,dc=example,dc=com",
        "domain": "example.com"
      }
    }

Reporting bugs and contributing
===============================

For bug reporting and contributing, please check the CONTRIBUTING.md file.
