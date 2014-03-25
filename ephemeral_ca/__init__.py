#!/usr/bin/env python
"""
FlaskCA
"""

import M2Crypto
import fcntl
import os
import sys
import time
import uuid
import yaml
import ldap

from flask import Flask, request, redirect, Response

app = Flask(__name__)
app.config.from_pyfile(os.environ.get('EPHEMERAL_CA_SETTINGS', 'config.cfg'))


def ldap_login(user, secret):
    ldo = ldap.initialize("ldap://%s" % (app.config['LDAP_HOST'],))
    ldo.set_option(ldap.OPT_REFERRALS, 0)
    try:
        ldo.simple_bind_s("%s@%s" % (user, app.config['LDAP_DOMAIN']), secret)
        return True
    except ldap.INVALID_CREDENTIALS:
        return False


def auth(user, secret):
    if app.config['BACKDOOR_AUTH']:
        if secret=='woot' and user=='woot':
            return True

    return ldap_login(user, secret)


def sign(csr,encoding):
    if encoding != 'pem':
        return False

    with open(app.config['SERIAL_FILE'], 'a+') as f:
        f.seek(0)
        fcntl.lockf(f, fcntl.LOCK_EX)
        serial = int(f.read() or "1")
        f.seek(0)
        f.truncate(0)
        f.write(str(serial+1))

    ca = M2Crypto.X509.load_cert(app.config["CA_CERT"])
    key = M2Crypto.EVP.load_key(app.config["CA_KEY"])
    req = M2Crypto.X509.load_request_string(csr.encode('ascii'))

    new_cert = M2Crypto.X509.X509()
    new_cert.set_version(0)

    now = int(time.time())
    start_time = M2Crypto.ASN1.ASN1_UTCTIME()
    start_time.set_time(now)
    end_time = M2Crypto.ASN1.ASN1_UTCTIME()
    end_time.set_time(now+(app.config['VALID_HOURS']*60*60))

    new_cert.set_not_before(start_time)
    new_cert.set_not_after(end_time)

    new_cert.set_pubkey(pkey=req.get_pubkey())
    new_cert.set_subject(req.get_subject())
    new_cert.set_issuer(ca.get_subject())
    new_cert.set_serial_number(serial)

    new_cert.sign(key, app.config['SIGNING_HASH'])

    new_cert.save(os.path.join(
        app.config['CERTS_DIRECTORY'],
        '%06i-%s.crt' % (serial, new_cert.get_fingerprint(app.config['SIGNING_HASH']))))

    return new_cert.as_pem()


@app.route("/")
def fail():
    return 'Nothing to see here\n', 404


@app.route("/robots.txt")
def robots():
    txt = "User-agent: *\nDisallow: /\n"
    return txt, 200


@app.route("/sign",methods=['POST'])
def sign_request():
    """
    for key in ('user','authtype','csr','encoding','secret'):
        if not request.args.has_key(key):
            print '%s key missing from request:' % key
            print request.args.keys()
            return 'Request is missing keys!\n', 500

    """
    if not auth(request.form['user'], request.form['secret']):
        return 'Authentication Failure\n', 403

    cert = sign(request.form['csr'],request.form['encoding'])
    if not cert:
        return 'Signing Failure\n', 500

    #TODO: Probably need some nice headers or some other schtuff
    return cert, 200


def run_server():
    app.run(
        host=app.config['BIND_HOST'],
        port=app.config['BIND_PORT'])
