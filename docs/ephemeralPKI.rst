Ephemeral PKI
=============

Anchor is a Certificate and Registration Authority built to provide ephemeral
PKI services for large scale infrastructure deployments such as OpenStack. It
exists to solve two problems that typically affect PKI deployments but that
often go ignored by users; securely provision certificates in live environments
is incredibly difficult and effectively revoking bad certificates is nearly
impossible with the cryptographic libraries that are available to handle PKI
operations today.

Traditional Provisioning
------------------------
One of the challenges for managing PKI in large infrastructures is ensuring
that certificates are provisioned securely and effectively. In traditional PKI
a certificate signing request (CSR) would be created by a user who requires a
certificate for some service that they are managing. The user would then
typically submit that CSR to whatever corporate PKI system is in use, likely
Dogtag_ or Active Directory Certificate Services (ADCS_). That submission would
then trigger a process of verification that often includes a PKI administrator
manually inspecting that the various fields within the CSR and approving the
issuing of a certificate. When the certificate is issued the original requestor
needs to be notified, often by way of email - the requestor then accesses the
CA and retrieves their newly signed certificate.

.. _Dogtag: http://pki.fedoraproject.org/wiki/PKI_Main_Page
.. _ADCS: https://technet.microsoft.com/en-us/windowsserver/dd448615.aspx

This heavily manual process is fraught with opportunities for human error and
tends to scale very poorly. This workflow may have sufficed for managing the
certificates that an organization might want to provision at it's edge but it
cannot cope with the massive number of certificates required for running large
data centers.

Methods for automatically issuing certificates such as SCEP and ADCS
auto-enrollment exist to help solve this problem but often require significant
architectural changes to use them securely. For example, SCEP requires a
secure network to work (in most cases, if such a network already exists then
certificates would not be necessary) so it is typically only used when
infrastructure is provisioned - before being moved into production. ADCS
auto-enrollment requires all of  your servers to be running on Microsoft
Windows, which is often not the case for large scale cloud-type environments.

Anchor provides an alternative mechanism for provisioning certificates that
allows each server in a cluster to request its own certificate while
enforcing strong issuing policies that introduce capabilities beyond those that
can be leveraged by the manual process described above - and it can do it at
large scale.

Anchor Provisioning
-------------------
Anchor expects that a machine which requires a certificate will request it
directly, rather than some user requesting it and then installing it on the
machine. This requires the machine to somehow track existing certificates and
request new ones when they expire. There are many ways to approach this and
often a simple cron.d bash script will suffice. The Cathead_ and Certmonger_
projects both exist to help with system based certificate management but only
Cathead natively supports Anchor, however Certmonger can be modified to work
with Anchor if required.

.. _Cathead: https://github.com/stackforge/cathead
.. _Certmonger: https://fedorahosted.org/certmonger/

Anchor provides multiple ways for machines to authenticate. The currently
supported options are LDAP, Keystone and a pre-shared Username/Password
combination. As every machine in a data centre can potentially have it's own
set of credentials Anchor can make very fine grained decisions regarding which
machines should be trusted at any given time. There's more information on
Anchor authentication in the :doc:`configuration` section.

Along with fine grained access control Anchor, supports various
:doc:`validators` that can be used by PKI administrators to set tight policy
constraints on what is allowed within a certificate. These validators provide a
powerful construct for programmatically verifying that a certificate meets
policy requirements for a particular environment.

Traditional Revocation
----------------------
Certificates can require revocation for a number of reasons, they may no longer
be required, they may have been incorrectly issued or the private key for a
certificate may have been compromised.

There are two methods that exist for revoking certificates; Certificate
Revocation Lists (CRL_) and the Online Certificate Status Protocol (OCSP_).
Unfortunately neither system is particularly robust when attempting to use them
within dynamic, large scale environments. CRLs are updated only periodically
and have significant scale issues when used within systems that change
certificates regularly. OCSP was created to address a number of the issues that
hinder CRLs but unfortunately is very poorly supported in cryptographic
libraries outside of web-browser software. Using OCSP incurs some
infrastructure overhead because it needs to maintain a level of availability
that normally requires it to be load balanced to ensure that a responder is
always available, not receiving an OCSP response will cause a client to not
trust a certificate.

.. _CRL: https://www.ietf.org/rfc/rfc5280.txt
.. _OCSP: https://tools.ietf.org/html/rfc6960

To recap; CRLs do not work terribly well in large scale, dynamic environments
where multiple certificates might be required in a machine's lifetime as it is
repurposed. OCSP doesn't work outside of web browsers and is of little value
as a revocation system for large scale infrastructure.

Passive Revocation
------------------
During our testing of TLS client libraries it became obvious that OCSP was
poorly supported and that CRLs weren't reliable enough to provide strong
assurance that certificates would be revoked when required. We did observe that
expired certificates were correctly handled in the most common TLS libraries.
Anchor leverages expiry dates and issues very short lifetime certificates,
typically certificates will be issued with an expiry date set just 12-24 hours
into the future.

Rather than attempting to actively revoke a certificate in the tradition sense,
Anchor will refuse to re-issue a certificate to a bad machine or user. The
assumption being that a change in policy, or modification to the authentication
platform is all that is required to ensure that a bad actor cannot gain access
to certificates. We refer to this process as "Passive Revocation".

When using passive revocation one accepts that there is a certain window of
compromise when a "bad" certificate may still be used within the system.
Although this may seem like a sub-optimal way to handle revocation it actually
results in better performance than more traditional revocation techniques. As
discussed earlier, CRLs can be unreliable and OCSP is generally not supported
outside of web browsers. However, even if it were, the passive revocation
window typically employed by Anchor will be shorter than the OCSP cached
response when using an OCSP responder. This means that in most typical
configurations, using Anchor will result in more reliable and timely
certificate revocation than any other mechanism available today.
