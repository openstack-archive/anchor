from . import ldap
from . import keystone
from .results import AuthDetails, AUTH_FAILED

from pecan import conf

def validate(user, secret):
    if conf.auth['allow_backdoor']:
        if secret == 'woot' and user == 'woot':
            return AuthDetails(username='woot', groups=[])

    if conf.auth.get('ldap'):
        res = ldap.login(user, secret)
        if res is not AUTH_FAILED:
            return res

    if conf.auth.get('keystone'):
        res = keystone.login(secret)
        if res is not AUTH_FAILED:
            return res

    return AUTH_FAILED
