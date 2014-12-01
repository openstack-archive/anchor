Anchor
============

Anchor is an ephemeral PKI service that, based on certain conditions, automates the verification of CSRs and signs certificates for clients
The validity period can be set in the config file with hour resolution.

There are checks done against the certificate inside of the validate() function.
Currently some of the checks are: is the domain in CN ending with one of the suffixes allowed n the config file and does the server prefix match the ldap user's team (for example is "nv-..." requested by a member of "Nova\_Team".

Installation
============

This service requires either a python virtual environment and python/ssl/ldap/sasl development system packages, or system python-ldap, python-pecan packages.

For virtual environment run:

    virtualenv .venv
    . .venv/bin/activate

To install a development version, run:

    pip install -e '.[develop]'

To install a production version with some authentication backend, run (where `auth_xxx` may be `auth_keystone` and/or `auth_ldap`):

    pip install '.[auth_xxx]'

The chosen authentication backend is only enabled if it's defined in the config file. The config file should be copied from `config.py` with any details updated.

The service can be run during development with:

    .venv/bin/pecan serve --reload config.py

In production, the package should be instead installed using:

    pip install '.[production]'

And the debug option in `config.py` has to be turned off. Service can be started via the uwsgi server, for example (with 4 processes):

    uwsgi --http-socket :5000 --venv /path/to/the/virtualenv --pecan /path/to/config.py -p 4

To test the service, generate the certificate request and submit it using curl:

    openssl req -text -newkey rsa:384 -nodes -out some.name.hpcloud.net.csr
    curl http://0:5000/sign -F user=sso_username -F secret=sso_password -F encoding=pem -F 'csr=<some.name.hpcloud.net.csr'
