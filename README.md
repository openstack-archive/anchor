Anchor
============

Anchor is an ephemeral PKI service that, based on certain conditions,
automates the verification of CSRs and signs certificates for clients.
The validity period can be set in the config file with hour resolution.

Installation
============

This service requires either a python virtual environment and
python/ssl/ldap/sasl development system packages, or system
python-ldap, python-pecan packages.

For virtual environment run:

    virtualenv .venv
    . .venv/bin/activate

To install a development version of Anchor, run:

    python setup.py develop
    pip install watchdog

Note that watchdog is needed only when running with the --reload option used
later. To install a production version, run:

    python setup.py install

The config file should be copied from `config.py` with any details updated.

Anchor requires you to provide a CA signing certificate and private key
which is stored in the CA subdirectory by default (as specified in
config.py). This can be generated using the certificate provider of
your choice, or a test signing certificate can be generated using
openssl:

Create a private key with password 'x', and then decrypt it:

    cd CA
    openssl genrsa -aes128 -passout pass:x -out ca.p.key 4096
    openssl rsa -passin pass:x -in ca.p.key -out root-ca-unwrapped.key

Then create a CSR from that key, specify 'Test Anchor CA' or similar as
the Common Name for the certificate:

    openssl req -new -key root-ca-unwrapped.key -out ca.csr

Finally, sign the CSR to create a self-signed root certificate:

    openssl x509 -req -days 365 -in ca.csr \
    -signkey root-ca-unwrapped.key -out root-ca.crt
    rm ca.p.key ca.csr

The service can be run during development with:

    .venv/bin/pecan serve --reload config.py

In production, the package should be instead installed using:

    pip install '.[production]'

And the debug option in `config.py` has to be turned off. Service can
be started via the uwsgi server, for example (with 4 processes):

    uwsgi --http-socket :5000 --venv /path/to/the/virtualenv \
    --pecan /path/to/config.py -p 4

To test the service, generate the certificate request using default
values and submit it using curl (change the user and secret if you have
changed them in config.py):

    openssl req -text -newkey rsa:4096 -nodes \
    -out subdomain.example.com.csr

    curl http://127.0.0.1:5000/sign -F user='woot' -F secret='woot' \
    -F encoding=pem -F 'csr=<subdomain.example.com.csr'

Assuming the installation is successful and the default config is
unchanged, this will fail validation, but should not give an OpenSSL or
other error. Now generate a valid CSR that should pass validation and
check that it is issued, by specifying a common name of
'anchor-test.example.com' when prompted:

    openssl req -text -newkey rsa:4096 -nodes \
    -out anchor-test.example.com.csr

    curl http://127.0.0.1:5000/sign -F user='woot' -F secret='woot' \
    -F encoding=pem -F 'csr=<anchor-test.example.com.csr'

If Anchor is correctly configured, the CA will return a certificate.

