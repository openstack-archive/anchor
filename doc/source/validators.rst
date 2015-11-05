Validators
==========

Currently validators can check three things: the CSR, the incoming connection,
and the authentication. The resulting action can be only pass or fail.
Validators are configured in the ``config.json`` file and each one comes with
different options.

Included validators
-------------------

The following validators are implemented at the moment:

``standards_compliance``
    Verifies: CSR.

    Ensures that the CSR does not break any rules defined in the standards
    documents (mostly RFC5280). Specific checks may be added over time in new
    versions of Anchor. This validator should be only skipped if there's a
    known compatibility issue. Otherwise it should be used in all environments.
    Any requests produced using standard tooling that fail this check should be
    reported as Anchor issues.

``whitelist_names``
    Verifies: CSR. Parameters:

    - ``names``: list of names/ips/ip ranges allowed in various fields
    - ``allow_cn_id``: allow name in subject CN
    - ``allow_dns_id``: allow name in SAN dns entry
    - ``allow_ip_id``: allow name in SAN IP entry
    - ``allow_wildcard``: allow wildcard certificate to match '%'

    IDs available in various places in the certificate are matched against the
    patterns in the ``names`` list. These can be:

    - IP addresses: ``1.2.3.4``
    - IP ranges: ``1.2.3.0/24``
    - complete names: ``some.example.com``
    - names with wildcards: ``%.example.com``, ``partial-%.example.com``

    Wildcard (``%``) rules: It matches only a single name label, or part of
    one. It can be used only in domain names, not IPs. Only one wildcard is
    allowed in a label, but multiple in a name, so ``%.%.example.com`` is
    valid.

    Pattern wildcard (``%``) may match a domain wildcard character (``*``)
    only if ``allow_wildcard`` is set to true.

    This match will fail if the CSR contains any SAN type not included here.

``blacklist_names``
    Verifies: CSR. Parameters: ``allowed_domains``, ``allowed_networks``.

    Ensures that the CN and subject alternative names do not contain anything
    configured in the ``domains``.

``common_name``
    Verifies: CSR. Parameters: ``allowed_domains``, ``allowed_networks``.

    Ensures that the CN matches one of names in ``allowed_domains`` or IP
    ranges in ``allowed_networks``.

    Deprecated: use ``whitelist_names`` / ``blacklist_names`` instead.

``alternative_names``
    Verifies: CSR. Parameters: ``allowed_domains``.

    Ensures that names specified in the subject alternative names extension
    match one of the names in ``allowed_domains``.

    Deprecated: use ``whitelist_names`` / ``blacklist_names`` instead.

``alternative_names_ip``
    Verifies: CSR. Parameters: ``allowed_domains``, ``allowed_networks``.

    Ensures that names specified in the subject alternative names extension
    match one of the names in ``allowed_domains`` or IP ranges in
    ``allowed_networks``.

    Deprecated: use ``whitelist_names`` / ``blacklist_names`` instead.

``server_group``
    Verifies: Auth, CSR. Parameters: ``group_prefixes``.

    Ensures the requester is authorised to get a certificate for a given
    server. This is currently assuming specific server naming scheme which
    looks like ``{prefix}-{name}.{domain}``. For example if the prefixes are
    defined as ``{"Nova": "nv"}``, and the client authentication returns group
    "Nova", then a request for ``nv-compute1.domain`` will succeed, but a
    request for ``gl-api1.domain`` will fail.

    Only CN is checked and if there are no dashes in the CN, validation
    succeeds.

    Deprecated: use ``whitelist_names`` / ``blacklist_names`` instead.

``extensions``
    Verifies: CSR. Parameters: ``allowed_extensions``.

    Ensures that only ``allowed_extensions`` are present in the request. The
    names recognised by Anchor are:

    policyConstraints, basicConstraints, subjectDirectoryAttributes,
    deltaCRLIndicator, cRLDistributionPoints, issuingDistributionPoint,
    nameConstraints, certificatePolicies, policyMappings,
    privateKeyUsagePeriod, keyUsage, authorityKeyIdentifier,
    subjectKeyIdentifier, certificateIssuer, subjectAltName, issuerAltName

    Alternatively, the extension can be specified by the dotted decimal version
    of OID.

``key_usage``
    Verifies: CSR. Parameters: ``allowed_usage``.

    Ensures only ``allowed_usage`` is requested for the certificate. The names
    recognised by Anchor are:

    Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment,
    Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only,

    as well as short versions:

    digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment,
    keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly

``ext_key_usage``
    Verifies: CSR. Parameters: ``allowed_usage``.

    Ensures only ``allowed_usage`` is requested for the certificate. The names
    recognised by Anchor are:

    TLS Web Server Authentication, TLS Web Client Authentication, Code Signing,
    E-mail Protection, Time Stamping, OCSP Signing, Any Extended Key Usage

    as well as short versions:

    serverAuth, clientAuth, codeSigning, emailProtection, timeStamping,
    ocspSigning, anyExtendedKeyUsage

    or text representation of custom OIDs.

``source_cidrs``
    Verifies: CSR. Parameters: ``cidrs``.

    Ensures the request comes from one of the ranges in `cidrs`.

``public_key``
    Verifies: CSR. Parameters: ``allowed_keys``.

    Ensures that only selected keys of a minimum specified length can be used
    in the CSR. The ``allowed_keys`` parameter is a dictionary where keys are
    the uppercase key names and values are minimum key lengths. Valid keys
    at the moment are: ``RSA`` and ``DSA``.

Extension interface
-------------------

Custom validators can be used with Anchor without changing the application
itself. All validators are exposed as Stevedore_ extensions. They're registered
as entry points in namespace ``anchor.validators`` and each name points to a
simple function which accepts the following keyword arguments:

``csr`` : anchor.X509.signing_request.X509Csr
    An object describing the submitted CSR.

``auth_result`` : anchor.auth.results.AuthDetails
    An object which contains authentication information like username and user
    groups.

``request`` : pecan.Request
    The https request which delivered the CSR.

``conf`` : dict
    Dictionary describing the registration authority configuration.

On successful return, the request is passed on to the next validator or signed
if there are no remining ones. On validation failure an
``anchor.validators.ValidationError``  exception must be raised.

.. _Stevedore: http://docs.openstack.org/developer/stevedore/index.html
