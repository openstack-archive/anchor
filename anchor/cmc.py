from anchor.asn1 import rfc5652
from anchor.asn1 import rfc6402

from pyasn1.codec.der import decoder
from pyasn1 import error


class CMCParsingError(Exception):
    pass


class UnexpectedContentType(CMCParsingError):
    def __init__(self, content_type):
        self.content_type = content_type

    def __str__(self):
        return "Unexpected content type, got %s" % self.content_type


def _unwrap_signed_data(data):
    # Since we don't have trust with anyone signing the requests, this
    # signature is not relevant. The request itself is self-signed which
    # stops accidents.
    result = decoder.decode(data, rfc5652.SignedData())[0]
    return _unwrap_generic(
        result['encapContentInfo']['eContentType'],
        result['encapContentInfo']['eContent'])


def _unwrap_content_info(data):
    result = decoder.decode(data, rfc5652.ContentInfo())[0]
    return _unwrap_generic(result['contentType'], result['content'])


def _unwrap_generic(content_type, data):
    unwrapper = CONTENT_TYPES.get(content_type)
    if unwrapper is None:
        return (content_type, data)
    return unwrapper(data)


def strip_wrappers(data):
    # assume the outer wrapper is contentinfo
    return _unwrap_content_info(data)


CONTENT_TYPES = {
    rfc5652.id_ct_contentInfo: _unwrap_content_info,
    rfc5652.id_signedData: _unwrap_signed_data,
}


def parse_request(data):
    try:
        content_type, data = strip_wrappers(data)
    except error.PyAsn1Error:
        raise CMCParsingError("Cannot find valid CMC wrapper")

    if content_type != rfc6402.id_cct_PKIData:
        raise UnexpectedContentType(content_type)

    pd = decoder.decode(data, rfc6402.PKIData())[0]
    if len(pd['reqSequence']) == 0:
        raise CMCParsingError("No certificate requests")
    if len(pd['reqSequence']) > 1:
        raise CMCParsingError("Can't handle multiple certificates")
    req = pd['reqSequence'][0]

    if req.getName() != 'tcr':
        raise CMCParsingError("Can handle only tagged cert requests")

    return req['tcr']['certificationRequest']


if __name__ == "__main__":
    import sys
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    cert_req = parse_request(data)
    print(cert_req.prettyPrint())
