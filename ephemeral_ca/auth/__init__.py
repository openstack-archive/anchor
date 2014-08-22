from .results import AuthDetails, AUTH_FAILED

from pecan import conf

if conf.auth.get('ldap'):
    from . import ldap

if conf.auth.get('keystone'):
    from . import keystone


def validate(user, secret):
    if conf.auth.get('static'):
        if secret == conf.auth['static']['secret'] and user == conf.auth['static']['user']:
            return AuthDetails(username=conf.auth['static']['user'], groups=[])

    if conf.auth.get('ldap'):
        res = ldap.login(user, secret)
        if res is not AUTH_FAILED:
            return res

    if conf.auth.get('keystone'):
        res = keystone.login(secret)
        if res is not AUTH_FAILED:
            return res

    return AUTH_FAILED
