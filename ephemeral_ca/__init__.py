#!/usr/bin/env python
"""
FlaskCA
"""

import M2Crypto
import sys
import time
import uuid
import yaml

from flask import Flask, request, redirect, Response

CONFIG = {}
app = Flask(__name__)


#ToDo: Write some actual authentication routines.
def auth(secret,user,authtype):
    if authtype == 'bypass-backdoor':
        if secret=='woot' and user=='woot':
            return True

        return False


def sign(csr,encoding):
    if encoding != 'pem':
        return False

    ca = M2Crypto.X509.load_cert(CONFIG["ca_cert"])
    key = M2Crypto.EVP.load_key(CONFIG["ca_key"])
    req = M2Crypto.X509.load_request_string(csr.encode('ascii'))

    new_cert = M2Crypto.X509.X509()
    new_cert.set_version(0)

    now = int(time.time())
    start_time = M2Crypto.ASN1.ASN1_UTCTIME()
    start_time.set_time(now)
    end_time = M2Crypto.ASN1.ASN1_UTCTIME()
    end_time.set_time(now+(CONFIG['valid_hours']*60*60))

    new_cert.set_not_before(start_time)
    new_cert.set_not_after(end_time)

    new_cert.set_pubkey(pkey=req.get_pubkey())
    new_cert.set_subject(req.get_subject())
    new_cert.set_issuer(ca.get_subject())
    new_cert.set_serial_number(31337)

    new_cert.sign(key, CONFIG['signing_hash'])

    new_cert.save("temp-" + str(uuid.uuid1()) + '.crt')

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
    if not auth(request.form['secret'],request.form['user'],request.form['authtype']):
        return 'Authentication Failure\n', 403

    cert = sign(request.form['csr'],request.form['encoding'])
    if not cert:
        return 'Signing Failure\n', 500

    #TODO: Probably need some nice headers or some other schtuff
    return cert, 200


def read_config(path):
    global CONFIG
    with open(path, 'r') as f:
        CONFIG = yaml.load(f)


def run_server():
    read_config(sys.argv[1] if len(sys.argv) > 1 else 'config.yaml')
    app.run(
        debug=CONFIG['flask_debug'],
        host=CONFIG['bind_host'],
        port=CONFIG['bind_port'])
