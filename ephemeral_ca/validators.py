import M2Crypto


class ValidationError(Exception):
    pass


def csr_get_cn(csr):
    return str(csr.get_subject().get_entries_by_nid(M2Crypto.X509.X509_Name.nid['CN'])[0].get_data())


def check_domain(app, domain):
    if not any(domain.endswith(suffix) for suffix in app.config['ALLOWED_DOMAINS']):
        raise ValidationError("Domain '%s' not allowed" % domain)


def common_name(csr=None, app=None, **kwargs):
    """
    Refuse requests for certificates if they contain multiple CN
    entries, or the domain does not match the list of known suffixes.
    """

    alt_present = any(ext.get_name() == "subjectAltName" for ext in (csr.get_extensions() or []))
    CNs = csr.get_subject().get_entries_by_nid(M2Crypto.X509.X509_Name.nid['CN'])

    if alt_present:
        if len(CNs) > 1:
            raise ValidationError("Too many CNs in the request")
    else:
        # rfc5280#section-4.2.1.6 says so
        if len(csr.get_subject()) == 0:
            raise ValidationError("Alt subjects have to exist if the main subject doesn't")

    if len(CNs) > 0:
        cn = csr_get_cn(csr)
        check_domain(app, cn)


def alternative_names(csr=None, app=None, **kwargs):
    """
    Refuse requests for certificates if the domain does not match
    the list of known suffixes.
    """
    for ext in (csr.get_extensions() or []):
        if ext.get_name() == "subjectAltName":
            alternatives = [alt.strip() for alt in ext.get_value().split(',')]
            for alternative in alternatives:
                parts = alternative.split(':', 1)
                if len(parts) != 2 or parts[0] != 'DNS':
                    raise ValidationError("Alt name '%s' does not have a known type")
                check_domain(app, parts[1])


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


def extensions(csr=None, app=None, **kwargs):
    """
    Ensure only accepted extensions are used
    """
    exts = csr.get_extensions() or []
    for ext in exts:
        if ext.get_name() not in app.config['ALLOWED_EXTENSIONS']:
            raise ValidationError("Extension '%s' not allowed" % ext.get_name())


def key_usage(csr=None, app=None, **kwargs):
    """
    Ensure only accepted key usages are specified
    """
    allowed = set(app.config['ALLOWED_USAGE'])

    for ext in (csr.get_extensions() or []):
        if ext.get_name() == 'keyUsage':
            usages = set(usage.strip() for usage in ext.get_value().split(','))
            if usages & allowed != usages:
                raise ValidationError("Found some not allowed key usages")
