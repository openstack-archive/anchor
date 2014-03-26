Ephemeral CA
============

This service generates quickly expiring certificates for a given CA.
The validity period can be set in the config file with hour resolution.

There are checks done against the certificate inside of the validate() function.
Currently some of the checks are: is the domain in CN ending with one of the suffixes allowed n the config file and does the server prefix match the ldap user's team (for example is "nv-..." requested by a member of "Nova\_Team".

Installation
============

This service requires either a python virtual environment and python/ssl/ldap/sasl development system packages, or system python-ldap, python-flask packages.

For virtual environment run:

    virtualenv .venv
    . .venv/bin/activate
    ./setup.py develop

The config file should be copied from `config.cfg.sample` to `ephemeral\_ca/config.cfg` with any details updated.

The service can be run with:

    ephemeral_ca_server

To test the service, generate the certificate request and submit it using curl:

    openssl req -text -newkey rsa:384 -nodes -out some.name.hpcloud.net.csr
    curl http://0:5000/sign -F user=sso_username -F secret=sso_password -F encoding=pem -F 'csr=<some.name.hpcloud.net.csr'
