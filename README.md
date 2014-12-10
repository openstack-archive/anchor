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

Currently Anchor requires a modified varient of M2Crypto, which must be
installed manually. Prior to installing M2Crypto, SWIG must be
installed if this is not already present on your system. Test with:

    swig

If this results with 'command not found' or similar, then install swig
by downloading from http://www.swig.org/download.html or using your
preferred package manager. Download and install the modified M2crypto:

    git clone https://github.com/viraptor/M2Crypto.git
    cd M2Crypto
    python setup.py build && python setup.py install
    cd ..

 Depending on your platform, you may need to add a link between the
 location of your openssl libraries and the path used by swig:
 (/usr/include)

To install a development version of Anchor, run:

    pip install -e '.[develop]'

To install a production version with some authentication backend, run
(where `auth_xxx` may be `auth_keystone` and/or `auth_ldap`):

    pip install '.[auth_xxx]'

The chosen authentication backend is only enabled if it's defined in
the config file. The config file should be copied from `config.py` with
any details updated.

Anchor requires you to provide a CA signing certificate and private key
which is stored in the CA subdirectory by default (as specified in
config.py). This can be generated using the certificate provider of
your choice, or a test signing certificate can be generated using
openssl:

Create a private key:

    cd CA
    openssl genrsa -des3 -passout pass:x -out ca.p.key 2048
    openssl rsa -passin pass:x -in ca.p.key -out root-ca-unwrapped.key

Then create a CSR from that key, specify 'Test Anchor CA' or similar as
the Common Name for the certificate:
    openssl req -new -key root-ca-unwrapped.key -out ca.csr
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

    openssl req -text -newkey rsa:384 -nodes \
    -out some.name.hpcloud.net.csr

    curl http://127.0.0.1:5000/sign -F user='woot' -F secret='woot' \
    -F encoding=pem -F 'csr=<some.name.hpcloud.net.csr'

Assuming the installation is successful and the default config is
unchanged, this will fail validation, but should not give a M2Crypto or
other error. Now generate a valid csr that should pass validation and
check that it is issued, by specifying a common name of
'valid.cert.anchor.test' when prompted:

    openssl req -text -newkey rsa:384 -nodes \
    -out valid.cert.anchor.test.csr

    curl http://127.0.0.1:5000/sign -F user='woot' -F secret='woot' \
    -F encoding=pem -F 'csr=<valid.cert.anchor.test'

If Anchor is correctly configured, the CA will return a certificate.

