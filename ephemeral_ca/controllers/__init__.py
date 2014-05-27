from pecan import expose, request, response
from ephemeral_ca import auth, certificate_ops, validators


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
            response.status_int = 401
            return

        csr = certificate_ops.parse_csr(request.POST.get('csr'), request.POST.get('encoding'))
        if csr is None:
            response.status_int = 400
            return 'CSR cannot be parsed\n'

        try:
            certificate_ops.validate_csr(auth_result, csr)
        except validators.ValidationError as e:
            response.status_int = 409
            return 'Validation failed: %s\n' % e

        cert = certificate_ops.sign(csr)
        if not cert:
            response.status_int = 500
            return 'Signing Failure\n'
    
        return cert
