#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import ldap
import ldap.filter

from anchor.auth import results
from anchor import jsonloader


def user_get_groups(attributes):
    """Retrieve the group membership

    :param attributes: LDAP attributes for user
    :returns: List -- A list of groups that the user is a member of
    """
    groups = attributes.get('memberOf', [])
    group_dns = [ldap.dn.explode_dn(g, notypes=True) for g in groups]
    return set(x[0] for x in group_dns if x[1] == 'Groups')


def login(user, secret):
    """Attempt to Authenitcate user using LDAP

    :param user: Username
    :param secret: Secret/Passphrase
    :returns: AuthDetails -- Class used for authentication information
    """
    ldo = ldap.initialize("ldap://%s" % (jsonloader.conf.auth['ldap']['host']))
    ldo.set_option(ldap.OPT_REFERRALS, 0)
    try:
        ldo.simple_bind_s("%s@%s" % (user,
                                     jsonloader.conf.auth['ldap']['domain']),
                          secret)

        filter_str = ('(sAMAccountName=%s)' %
                      ldap.filter.escape_filter_chars(user))
        ret = ldo.search_s(jsonloader.conf.auth['ldap']['base'],
                           ldap.SCOPE_SUBTREE,
                           filterstr=filter_str,
                           attrlist=['memberOf'])
        user_attrs = [x for x in ret if x[0] is not None][0][1]
        user_groups = user_get_groups(user_attrs)
        return results.AuthDetails(username=user, groups=user_groups)
    except ldap.INVALID_CREDENTIALS:
        return None
