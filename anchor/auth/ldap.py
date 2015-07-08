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

from __future__ import absolute_import

import ldap3
from ldap3.utils import dn

from anchor.auth import results
from anchor import jsonloader


def user_get_groups(attributes):
    """Retrieve the group membership

    :param attributes: LDAP attributes for user
    :returns: List -- A list of groups that the user is a member of
    """
    groups = attributes.get('memberOf', [])
    group_dns = [dn.parse_dn(g) for g in groups]
    return set(x[0][1] for x in group_dns if x[1] == ('OU', 'Groups', ','))


def login(user, secret):
    """Attempt to Authenitcate user using LDAP

    :param user: Username
    :param secret: Secret/Passphrase
    :returns: AuthDetails -- Class used for authentication information
    """
    ldap_port = int(jsonloader.conf.auth['ldap'].get('port', 389))
    use_ssl = jsonloader.conf.auth['ldap'].get('ssl', ldap_port == 636)

    lds = ldap3.Server(jsonloader.conf.auth['ldap']['host'], port=ldap_port,
                       get_info=ldap3.ALL, use_ssl=use_ssl)

    try:
        ldap_user = "%s@%s" % (user, jsonloader.conf.auth['ldap']['domain'])
        ldc = ldap3.Connection(lds, auto_bind=True, client_strategy=ldap3.SYNC,
                               user=ldap_user, password=secret,
                               authentication=ldap3.SIMPLE, check_names=True)

        filter_str = ('(sAMAccountName=%s)' %
                      ldap3.utils.conv.escape_bytes(user))
        ldc.search(jsonloader.conf.auth['ldap']['base'], filter_str,
                   ldap3.SUBTREE, attributes=['memberOf'])
        if ldc.result['result'] != 0:
            return None
        user_attrs = ldc.response[0]['attributes']
        user_groups = user_get_groups(user_attrs)
        return results.AuthDetails(username=user, groups=user_groups)
    except ldap3.LDAPBindError:
        return None
