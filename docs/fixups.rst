Fixups
======

Fixups can be used to modify submitted CSRs before sigining. That means for
example adding extra name elements, or extensions. Each fixup is loaded from
the "anchor.fixups" namespace using stevedore and gets access to the parsed CSR
and the configuration.

Unlike validators, each fixup has to return either a new CSR structure or the
modified original.
