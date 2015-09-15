Extension support
=================

Extensions in Anchor are supported on 3 levels:

* CSR parser (are OIDs recognised)
* validators / fixups which operate on extensions
* signing backends which operate on extensions

Anchor needs to parse the extension to use it in a validator or a fixup. That's
not the case of the signing backends however - external backends may add/update
extensions according to their own configuration.

Anchor can parse and analyse the following extensions:

* Basic Constraints
* Key Usage
* Subject Alternative Name

The following extensions are listed as required or preferred, but due to
Anchor's main purpose (ephemeral certificates) they will be either ignored (if
they're not critical), or will prevent signing (if they are):

* Certificate Policies
* Policy Mappings
* Inhibit anyPolicy
* CRL Distribution Points
* Freshest CRL

Other extensions will be added to the implementation when they're needed for
validation / fixups.
