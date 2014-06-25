from pecan import expose, request, response
from .. import auth, certificate_ops, validators

import logging

logger = logging.getLogger(__name__)

class RootController(object):

    @expose(content_type="text/plain")
    def robots(self):
        if request.method != "GET":
            response.status_int = 405
            return
        return "User-agent: *\nDisallow: /\n"

    @expose(content_type="text/plain")
    def sign(self):
        if request.method != "POST":
            response.status_int = 405
            return

        auth_result = auth.validate(request.POST.get('user'), request.POST.get('secret'))
        if auth_result is auth.AUTH_FAILED:
            logger.info("request failed authentication")
            response.status_int = 401
            return

        csr = certificate_ops.parse_csr(request.POST.get('csr'), request.POST.get('encoding'))
        if csr is None:
            logger.info("csr in the request cannot be parsed")
            response.status_int = 400
            return 'CSR cannot be parsed\n'

        try:
            certificate_ops.validate_csr(auth_result, csr)
        except validators.ValidationError as e:
            logger.exception("csr failed validation")
            response.status_int = 409
            return 'Validation failed: %s\n' % e

        cert = certificate_ops.sign(csr)
        if not cert:
            logger.error("certificate signing error")
            response.status_int = 500
            return 'Signing Failure\n'
    
        return cert
