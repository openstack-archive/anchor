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
import logging

import ldap3
from ldap3.utils import dn

from anchor.auth import results
from anchor import jsonloader


logger = logging.getLogger(__name__)


def user_get_groups(attributes):
    """Retrieve the group membership

    :param attributes: LDAP attributes for user
    :returns: List -- A list of groups that the user is a member of
    """
    groups = attributes.get('memberOf', [])
    group_dns = [dn.parse_dn(g) for g in groups]
    return [x[0][1] for x in group_dns if x[1] == ('OU', 'Groups', ',')]


def login(ra_name, user, secret):
    """Attempt to Authenitcate user using LDAP

    :param ra_name: name of registration authority
    :param user: Username
    :param secret: Secret/Passphrase
    :returns: AuthDetails -- Class used for authentication information
    """
    conf = jsonloader.authentication_for_registration_authority(ra_name)
    ldap_port = int(conf.get('port', 389))
    use_ssl = conf.get('ssl', ldap_port == 636)

    lds = ldap3.Server(conf['host'], port=ldap_port,
                       get_info=ldap3.ALL, use_ssl=use_ssl)

    try:
        ldap_user = "%s@%s" % (user, conf['domain'])
        ldc = ldap3.Connection(lds, auto_bind=True, client_strategy=ldap3.SYNC,
                               user=ldap_user, password=secret,
                               authentication=ldap3.SIMPLE, check_names=True)

        filter_str = ('(sAMAccountName=%s)' %
                      ldap3.utils.conv.escape_bytes(user))
        ldc.search(conf['base'], filter_str,
                   ldap3.SUBTREE, attributes=['memberOf'])
        if ldc.result['result'] != 0:
            return None
        user_attrs = ldc.response[0]['attributes']
        user_groups = user_get_groups(user_attrs)
        return results.AuthDetails(username=user, groups=user_groups)
    except ldap3.LDAPSocketOpenError:
        logger.error("cannot connect to LDAP host '%s' (authority '%s')",
                     conf['host'], ra_name)
        return None
    except ldap3.LDAPBindError:
        logger.info("failed ldap auth for user %s", user)
        return None
