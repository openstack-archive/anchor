import M2Crypto


class ValidationError(Exception):
    pass


def csr_get_cn(csr):
    return str(csr.get_subject().get_entries_by_nid(M2Crypto.X509.X509_Name.nid['CN'])[0].get_data())


def check_domain(domain, allowed_domains):
    if not any(domain.endswith(suffix) for suffix in allowed_domains):
        raise ValidationError("Domain '%s' not allowed" % domain)


def common_name(csr=None, allowed_domains=[], **kwargs):
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
        check_domain(cn, allowed_domains)


def alternative_names(csr=None, allowed_domains=[], **kwargs):
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
                check_domain(parts[1], allowed_domains)


def server_group(auth_result=None, csr=None, group_prefixes={}, **kwargs):
    """
    Make sure that for server names containing a team prefix, the team is
    verified against the groups the user is a member of.
    """

    cn = csr_get_cn(csr)
    parts = cn.split('-')
    if len(parts) == 1 or '.' in parts[0]:
        return  # no prefix

    if parts[0] in group_prefixes:
        if group_prefixes[parts[0]] not in auth_result.groups:
            raise ValidationError("Server prefix doesn't match user groups")


def extensions(csr=None, allowed_extensions=[], **kwargs):
    """
    Ensure only accepted extensions are used
    """
    exts = csr.get_extensions() or []
    for ext in exts:
        if ext.get_name() not in allowed_extensions:
            raise ValidationError("Extension '%s' not allowed" % ext.get_name())


def key_usage(csr=None, allowed_usage=None, **kwargs):
    """
    Ensure only accepted key usages are specified
    """
    allowed = set(allowed_usage)

    for ext in (csr.get_extensions() or []):
        if ext.get_name() == 'keyUsage':
            usages = set(usage.strip() for usage in ext.get_value().split(','))
            if usages & allowed != usages:
                raise ValidationError("Found some not allowed key usages: %s" % (usages - allowed))


def ca_status(csr=None, ca_requested=False, **kwargs):
    """
    Ensure the request has/hasn't got the CA flag
    """

    for ext in (csr.get_extensions() or []):
        ext_name = ext.get_name()
        if ext_name == 'basicConstraints':
            options = [opt.strip() for opt in ext.get_value().split(",")]
            for option in options:
                parts = option.split(":")
                if len(parts) != 2:
                    raise ValidationError("Invalid basic constraints flag")

                if parts[0] == 'CA':
                    if parts[1] != str(ca_requested).upper():
                        raise ValidationError("Invalid CA status, 'CA:%s' requested" % parts[1])
                elif parts[0] == 'pathlen':
                    # errr.. it's ok, I guess
                    pass
                else:
                    raise ValidationError("Invalid basic constraints option")
        elif ext_name == 'keyUsage':
            usages = set(usage.strip() for usage in ext.get_value().split(','))
            has_cert_sign = ('Certificate Sign' in usages)
            has_crl_sign = ('CRL Sign' in usages)
            if ca_requested != has_cert_sign or ca_requested != has_crl_sign:
                raise ValidationError("Key usage doesn't match requested CA status (keyCertSign/cRLSign: %s/%s)" % (has_cert_sign, has_crl_sign))
