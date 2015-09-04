Fixups
======

Fixups can be used to modify submitted CSRs before sigining. That means for
example adding extra name elements, or extensions. Each fixup is loaded from
the "anchor.fixups" namespace using stevedore and gets access to the parsed CSR
and the configuration.

Unlike validators, each fixup has to return either a new CSR structure or the
modified original.

Included fixups
---------------

The following fixups are implemented at the moment:

``enforce_alternative_names_present``
    Verifies: CSR.

    Ensures that if the certificate request contains a CN field in the subject,
    that same domain is also present in the subjectAlternativeNames extension.
    IP addresses are detected automatically.

    The extensions is added if it was missing.

    If no CN field is present, no changes are made.
