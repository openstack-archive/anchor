import M2Crypto


class ValidationError(Exception):
    pass


def csr_get_cn(csr):
    return str(csr.get_subject().get_entries_by_nid(M2Crypto.X509.X509_Name.nid['CN'])[0].get_data())


def server_name(csr=None, app=None, **kwargs):
    """
    Refuse requests for certificates if they contain multiple CN
    entries, or the domain does not match the list of known suffixes.
    """

    CNs = csr.get_subject().get_entries_by_nid(M2Crypto.X509.X509_Name.nid['CN'])
    if len(CNs) != 1:
        raise ValidationError("There should be one CN in request")

    cn = csr_get_cn(csr)
    if not any(cn.endswith(suffix) for suffix in app.config['ALLOWED_DOMAINS']):
        raise ValidationError("Domain suffix not allowed")


def server_group(auth_result=None, csr=None, app=None, **kwargs):
    """
    Make sure that for server names containing a team prefix, the team is
    verified against the groups the user is a member of.
    """

    cn = csr_get_cn(csr)
    parts = cn.split('-')
    if len(parts) == 1 or '.' in parts[0]:
        return  # no prefix

    if parts[0] in app.config['GROUP_PREFIXES']:
        if app.config['GROUP_PREFIXES'][parts[0]] not in auth_result.groups:
            raise ValidationError("Server prefix doesn't match user groups")


