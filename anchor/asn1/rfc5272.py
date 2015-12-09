from pyasn1.type import univ
from pyasn1.type import char
from pyasn1.type import namedtype
from pyasn1.type import constraint
from pyasn1.type import tag
from pyasn1.type import useful
from pyasn1.type import namedval

from pyasn1_modules import rfc2314
from pyasn1_modules import rfc2511
from pyasn1_modules import rfc2315
from pyasn1_modules import rfc2459
from . import rfc5652

MAX = 64

id_pkix = univ.ObjectIdentifier('1.3.6.1.5.5.7')
id_cmc = id_pkix + (7,)
id_cct = id_pkix + (12,)

# -- The following controls have the type OCTET STRING
id_cmc_identityProof = id_cmc + (3,)
id_cmc_dataReturn = id_cmc + (4,)
id_cmc_regInfo = id_cmc + (18,)
id_cmc_responseInfo = id_cmc + (19,)
id_cmc_queryPending = id_cmc + (21,)
id_cmc_popLinkRandom = id_cmc + (22,)
id_cmc_popLinkWitness = id_cmc + (23,)

# -- The following controls have the type UTF8String
id_cmc_identification = id_cmc + (2,)

# -- The following controls have the type INTEGER
id_cmc_transactionId = id_cmc + (5,)

# -- The following controls have the type OCTET STRING
id_cmc_senderNonce = id_cmc + (6,)
id_cmc_recipientNonce = id_cmc + (7,)

# -- This is the content type used for a request message in the protocol
id_cct_PKIData = id_cct + (2,)


bodyIdMax = 4294967295
class BodyPartID(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(1, bodyIdMax)

class AttributeValue(univ.Any):
    pass

class TaggedAttribute(univ.Sequence):
    """SEQUENCE {
        bodyPartID         BodyPartID,
        attrType           OBJECT IDENTIFIER,
        attrValues         SET OF AttributeValue
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('attrType', univ.ObjectIdentifier()),
        namedtype.NamedType('attrValues', univ.SetOf(
                componentType=AttributeValue()
            )
        ),
    )

class TaggedCertificationRequest(univ.Sequence):
    """SEQUENCE {
        bodyPartID            BodyPartID,
        certificationRequest  CertificationRequest
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('certificationRequest', rfc2314.CertificationRequest()),
    )

class TaggedRequest(univ.Choice):
    """CHOICE {
        tcr               [0] TaggedCertificationRequest,
        crm               [1] CertReqMsg,
        orm               [2] SEQUENCE {
            bodyPartID            BodyPartID,
            requestMessageType    OBJECT IDENTIFIER,
            requestMessageValue   ANY DEFINED BY requestMessageType
        }
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tcr', TaggedCertificationRequest().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )
        ),
        namedtype.NamedType('crm', rfc2511.CertReqMsg().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            )
        ),
        namedtype.NamedType('orm', univ.Sequence(
                componentType=namedtype.NamedTypes(
                    namedtype.NamedType('bodyPartID', BodyPartID()),
                    namedtype.NamedType('requestMessageType',
                        univ.ObjectIdentifier()),
                    namedtype.NamedType('requestMessageValue', univ.Any())
                )
            ).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
            )
        ),
    )

class TaggedContentInfo(univ.Sequence):
    """SEQUENCE {
        bodyPartID              BodyPartID,
        contentInfo             ContentInfo
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('contentInfo', rfc5652.ContentInfo()),
    )

class OtherMsg(univ.Sequence):
    """SEQUENCE {
         bodyPartID        BodyPartID,
         otherMsgType      OBJECT IDENTIFIER,
         otherMsgValue     ANY DEFINED BY otherMsgType }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('otherMsgType', univ.ObjectIdentifier()),
        namedtype.NamedType('otherMsgValue', univ.Any()),
    )

class PKIData(univ.Sequence):
    """PKIData ::= SEQUENCE {
        controlSequence    SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
        reqSequence        SEQUENCE SIZE(0..MAX) OF TaggedRequest,
        cmsSequence        SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
        otherMsgSequence   SEQUENCE SIZE(0..MAX) OF OtherMsg
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('controlSequence', univ.SequenceOf(
                componentType=TaggedAttribute()
            ).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(0, MAX)
            )
        ),
        namedtype.NamedType('reqSequence', univ.SequenceOf(
                componentType=TaggedRequest()
            ).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(0, MAX)
            )
        ),
        namedtype.NamedType('cmsSequence', univ.SequenceOf(
                componentType=TaggedContentInfo()
            ).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(0, MAX)
            )
        ),
        namedtype.NamedType('otherMsgSequence', univ.SequenceOf(
                componentType=OtherMsg()
            ).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(0, MAX)
            )
        ),
    )

# --  This defines the response message in the protocol
id_cct_PKIResponse = id_cct + (3,)

class PKIResponse(univ.Sequence):
    """SEQUENCE {
        controlSequence   SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
        cmsSequence       SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
        otherMsgSequence  SEQUENCE SIZE(0..MAX) OF OtherMsg
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('controlSequence', univ.SequenceOf(
                componentType=TaggedAttribute()
            ).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(0, MAX)
            )
        ),
        namedtype.NamedType('cmsSequence', univ.SequenceOf(
                componentType=TaggedContentInfo()
            ).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(0, MAX)
            )
        ),
        namedtype.NamedType('otherMsgSequence', univ.SequenceOf(
                componentType=OtherMsg()
            ).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(0, MAX)
            )
        ),
    )

ResponseBody = PKIResponse

# -- Used to return status state in a response
id_cmc_statusInfo = id_cmc + (1,)

class PendInfo(univ.Sequence):
    """SEQUENCE {
        pendToken        OCTET STRING,
        pendTime         GeneralizedTime
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pendToken', univ.OctetString()),
        namedtype.NamedType('pendTime', useful.GeneralizedTime()),
    )

    
class CMCStatus(univ.Integer):
    namedValues = namedval.NamedValues(
        ('success', 0),
        ('failed', 2),
        ('pending', 3),
        ('noSupport', 4),
        ('confirmRequired', 5),
        ('popRequired', 6),
        ('partial', 7)
    )

class CMCFailInfo(univ.Integer):
    namedValues = namedval.NamedValues(
        ('badAlg', 0),
        ('badMessageCheck', 1),
        ('badRequest', 2),
        ('badTime', 3),
        ('badCertId', 4),
        ('unsupportedExt', 5),
        ('mustArchiveKeys', 6),
        ('badIdentity', 7),
        ('popRequired', 8),
        ('popFailed', 9),
        ('noKeyReuse', 10),
        ('internalCAError', 11),
        ('tryLater', 12),
        ('authDataFail', 13)
    )

class CMCStatusInfo(univ.Sequence):
    """SEQUENCE {
        cMCStatus       CMCStatus,
        bodyList        SEQUENCE SIZE (1..MAX) OF BodyPartID,
        statusString    UTF8String OPTIONAL,
        otherInfo        CHOICE {
          failInfo         CMCFailInfo,
          pendInfo         PendInfo } OPTIONAL
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('cMCStatus', CMCStatus()),
        namedtype.NamedType('bodyList', univ.SequenceOf(
                componentType=BodyPartID()
            ).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX))
            ),
        namedtype.OptionalNamedType('statusString', char.UTF8String()),
        namedtype.OptionalNamedType('otherInfo', univ.Choice(
                componentType=namedtype.NamedTypes(
                    namedtype.NamedType('failInfo', CMCFailInfo()),
                    namedtype.NamedType('pendInfo', PendInfo()),
                )
            )
        ),
    )

# -- Used for RAs to add extensions to certification requests
id_cmc_addExtensions = id_cmc + (8,)

class AddExtensions(univ.Sequence):
    """SEQUENCE {
        pkiDataReference    BodyPartID,
        certReferences      SEQUENCE OF BodyPartID,
        extensions          SEQUENCE OF Extension
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pkiDataReference', BodyPartID()),
        namedtype.NamedType('certReferences', univ.SequenceOf(BodyPartID())),
        namedtype.NamedType('extensions', univ.SequenceOf(rfc2459.Extension())),
    )

id_cmc_encryptedPOP = id_cmc + (9,)
id_cmc_decryptedPOP = id_cmc + (10,)

class EncryptedPOP(univ.Sequence):
    """SEQUENCE {
        request       TaggedRequest,
        cms             ContentInfo,
        thePOPAlgID     AlgorithmIdentifier,
        witnessAlgID    AlgorithmIdentifier,
        witness         OCTET STRING
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('request', TaggedRequest()),
        namedtype.NamedType('cms', rfc5652.ContentInfo()),
        namedtype.NamedType('thePOPAlgID', rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('witnessAlgID', rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('witness', univ.OctetString()),
    )

class DecryptedPOP(univ.Sequence):
    """SEQUENCE {
        bodyPartID      BodyPartID,
        thePOPAlgID     AlgorithmIdentifier,
        thePOP          OCTET STRING
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('thePOPAlgID', rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('thePOP', univ.OctetString()),
    )

id_cmc_lraPOPWitness = id_cmc + (11,)

class LraPopWitness(univ.Sequence):
    """SEQUENCE {
        pkiDataBodyid   BodyPartID,
        bodyIds         SEQUENCE OF BodyPartID
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pkiDataBodyid', BodyPartID()),
        namedtype.NamedType('bodyIds', univ.SequenceOf(BodyPartID())),
    )

id_cmc_getCert = id_cmc + (15,)

class GetCert(univ.Sequence):
    """SEQUENCE {
        issuerName      GeneralName,
        serialNumber    INTEGER }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerName', rfc2459.GeneralName()),
        namedtype.NamedType('serialNumber', univ.Integer()),
    )

id_cmc_getCRL = id_cmc + (16,)

class GetCRL(univ.Sequence):
    """SEQUENCE {
        issuerName    Name,
        cRLName       GeneralName OPTIONAL,
        time          GeneralizedTime OPTIONAL,
        reasons       ReasonFlags OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerName', rfc2459.Name()),
        namedtype.OptionalNamedType('cRLName', rfc2459.GeneralName()),
        namedtype.OptionalNamedType('time', useful.GeneralizedTime()),
        namedtype.OptionalNamedType('reasons', rfc2459.ReasonFlags()),
    )

id_cmc_revokeRequest = id_cmc + (17,)

class RevokeRequest(univ.Sequence):
    """SEQUENCE {
        issuerName            Name,
        serialNumber          INTEGER,
        reason                CRLReason,
        invalidityDate         GeneralizedTime OPTIONAL,
        passphrase            OCTET STRING OPTIONAL,
        comment               UTF8String OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerName', rfc2459.Name()),
        namedtype.NamedType('serialNumber', univ.Integer()),
        namedtype.NamedType('reason', rfc2459.CRLReason()),
        namedtype.OptionalNamedType('invalidityDate', useful.GeneralizedTime()),
        namedtype.OptionalNamedType('passphrase', univ.OctetString()),
        namedtype.OptionalNamedType('comment', char.UTF8String()),
    )

id_cmc_confirmCertAcceptance = id_cmc + (24,)

class CMCCertId(rfc2315.IssuerAndSerialNumber):
    pass

# -- The following is used to request V3 extensions be added to a
# -- certificate
id_ExtensionReq = univ.ObjectIdentifier("1.2.840.113549.1.9.14")

class ExtensionReq(univ.SequenceOf):
    componentType = rfc2459.Extension()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)

# -- The following exists to allow Diffie-Hellman Certification Requests
# -- Messages to be well-formed
id_alg_noSignature = id_pkix + (6, 2)
NoSignatureValue = univ.OctetString()


# --  Unauthenticated attribute to carry removable data.
# --    This could be used in an update of "CMC Extensions: Server Side
# --    Key Generation and Key Escrow" (February 2005) and in other
# --    documents.
id_aa = univ.ObjectIdentifier("1.2.840.113549.1.9.16.2")
id_aa_cmc_unsignedData = id_aa + (34,)

class BodyPartPath(univ.SequenceOf):
    componentType = BodyPartID()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)

class CMCUnsignedData(univ.Sequence):
    """SEQUENCE {
        bodyPartPath        BodyPartPath,
        identifier          OBJECT IDENTIFIER,
        content             ANY DEFINED BY identifier
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartPath', BodyPartPath()),
        namedtype.NamedType('identifier', univ.ObjectIdentifier()),
        namedtype.NamedType('content', univ.Any()),
    )

# --  Replaces CMC Status Info
id_cmc_statusInfoV2 = id_cmc + (25,)

class BodyPartReference(univ.Choice):
    """CHOICE {
       bodyPartID           BodyPartID,
       bodyPartPath         BodyPartPath
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyPartID', BodyPartID()),
        namedtype.NamedType('bodyPartPath', BodyPartPath()),
    )

class CMCStatusInfoV2(univ.Sequence):
    """SEQUENCE {
       cMCStatus             CMCStatus,
       bodyList              SEQUENCE SIZE (1..MAX) OF
                                      BodyPartReference,
       statusString          UTF8String OPTIONAL,
       otherInfo             CHOICE {
         failInfo               CMCFailInfo,
         pendInfo               PendInfo,
         extendedFailInfo       SEQUENCE {
            failInfoOID            OBJECT IDENTIFIER,
            failInfoValue          AttributeValue
         }
       } OPTIONAL
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('cMCStatus', CMCStatus()),
        namedtype.NamedType('odyList', univ.SequenceOf(
                componentType=BodyPartReference()
            ).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX))
            ),
        namedtype.OptionalNamedType('statusString', char.UTF8String()),
        namedtype.OptionalNamedType('otherInfo', univ.Choice(
                componentType=namedtype.NamedTypes(
                    namedtype.NamedType('failInfo', CMCFailInfo()),
                    namedtype.NamedType('pendInfo', PendInfo()),
                    namedtype.NamedType('extendedFalInfo', univ.Sequence(
                        componentType=namedtype.NamedTypes(
                            namedtype.NamedType('failInfoOID', univ.ObjectIdentifier()),
                            namedtype.NamedType('failInfoValue', AttributeValue()),
                            )
                        )
                    )
                )
            )
        ),
    )

# --  Allow for distribution of trust anchors
id_cmc_trustedAnchors = id_cmc + (26,)

class PublishTrustAnchors(univ.Sequence):
    """SEQUENCE {
        seqNumber      INTEGER,
        hashAlgorithm  AlgorithmIdentifier,
        anchorHashes     SEQUENCE OF OCTET STRING
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seqNumber', univ.Integer()),
        namedtype.NamedType('hashAlgorithm', rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('anchorHashes', univ.SequenceOf(univ.OctetString)),
    )

id_cmc_authData = id_cmc + (27,)

AuthPublish = BodyPartID

# --   These two items use BodyPartList
id_cmc_batchRequests = id_cmc + (28,)
id_cmc_batchResponses = id_cmc + (29,)

class BodyPartList(univ.SequenceOf):
    componentType = BodyPartID()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, MAX)

id_cmc_publishCert = id_cmc + (30,)

class CMCPublicationInfo(univ.Sequence):
    """SEQUENCE {
        hashAlg                      AlgorithmIdentifier,
        certHashes                   SEQUENCE OF OCTET STRING,
        pubInfo                          PKIPublicationInfo
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashAlg', rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('certHashes', univ.SequenceOf(univ.OctetString)),
        namedtype.NamedType('pubInfo', rfc2511.PKIPublicationInfo()),
    )

id_cmc_modCertTemplate = id_cmc + (31,)

class ModCertTemplate(univ.Sequence):
    """SEQUENCE {
        pkiDataReference             BodyPartPath,
        certReferences               BodyPartList,
        replace                      BOOLEAN DEFAULT TRUE,
        certTemplate                 CertTemplate
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pkiDataReference', BodyPartPath()),
        namedtype.NamedType('certReferences', BodyPartList()),
        namedtype.DefaultedNamedType('replace', univ.Boolean('True')),
        namedtype.NamedType('certTemplate', rfc2511.CertTemplate()),
    )

# -- Inform follow on servers that one or more controls have already been
# -- processed
id_cmc_controlProcessed = id_cmc + (32,)

class ControlsProcessed(univ.Sequence):
    """SEQUENCE {
        bodyList              SEQUENCE SIZE(1..MAX) OF BodyPartReference
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyList', univ.SequenceOf(
            componentType=BodyPartReference()
        ).subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
        )),
    )

# --  Identity Proof control w/ algorithm agility
id_cmc_identityProofV2 = id_cmc + (34,)

class IdentifyProofV2(univ.Sequence):
    """SEQUENCE {
        proofAlgID       AlgorithmIdentifier,
        macAlgId         AlgorithmIdentifier,
        witness          OCTET STRING
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('proofAlgID', rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('macAlgId', rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('witness', univ.OctetString()),
    )

id_cmc_popLinkWitnessV2 = id_cmc + (33,)

class PopLinkWitnessV2(univ.Sequence):
    """SEQUENCE {
        keyGenAlgorithm   AlgorithmIdentifier,
        macAlgorithm      AlgorithmIdentifier,
        witness           OCTET STRING
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keyGenAlgorithm', rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('macAlgorithm', rfc2459.AlgorithmIdentifier()),
        namedtype.NamedType('witness', univ.OctetString()),
    )
