from collections import namedtuple

import ldap
import ldap.filter
from pecan import conf


AuthDetails = namedtuple('AuthDetails', ['username', 'groups'])
AUTH_FAILED = object()


def ldap_user_get_groups(attributes):
    groups = attributes.get('memberOf', [])
    group_dns = [ldap.dn.explode_dn(g, notypes=True) for g in groups]
    return set(x[0] for x in group_dns if x[1] == 'Groups')


def ldap_login(user, secret):
    ldo = ldap.initialize("ldap://%s" % (conf.auth['ldap']['host'],))
    ldo.set_option(ldap.OPT_REFERRALS, 0)
    try:
        ldo.simple_bind_s("%s@%s" % (user, conf.auth['ldap']['domain']), secret)

        filter_str = '(sAMAccountName=%s)' % ldap.filter.escape_filter_chars(user)
        ret = ldo.search_s(conf.auth['ldap']['base'], ldap.SCOPE_SUBTREE,
                           filterstr=filter_str, attrlist=['memberOf'])
        user_attrs = [x for x in ret if x[0] is not None][0][1]
        user_groups = ldap_user_get_groups(user_attrs)
        return AuthDetails(username=user, groups=user_groups)
    except ldap.INVALID_CREDENTIALS:
        return AUTH_FAILED


def validate(user, secret):
    if conf.auth['allow_backdoor']:
        if secret == 'woot' and user == 'woot':
            return AuthDetails(username='woot', groups=[])

    if conf.auth.get('ldap'):
        res = ldap_login(user, secret)
        if res is not AUTH_FAILED:
            return res

    return AUTH_FAILED
