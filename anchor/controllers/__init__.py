#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from pecan import expose
from pecan import request
from pecan import response
from pecan.rest import RestController

from .. import auth
from .. import certificate_ops
from .. import validators

import logging

logger = logging.getLogger(__name__)


class RobotsController(RestController):
    """Serves /robots.txt that disallows search bots."""

    @expose(content_type="text/plain")
    def get(self):
        return "User-agent: *\nDisallow: /\n"


class SignController(RestController):
    """Handles POST requests to /sign."""

    @expose(content_type="text/plain")
    def post(self):
        auth_result = auth.validate(request.POST.get('user'),
                                    request.POST.get('secret'))

        csr = certificate_ops.parse_csr(request.POST.get('csr'),
                                        request.POST.get('encoding'))
        if csr is None:
            logger.info("csr in the request cannot be parsed")
            response.status_int = 400
            return 'CSR cannot be parsed\n'

        try:
            certificate_ops.validate_csr(auth_result, csr, request)
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


class RootController(object):
    robots = RobotsController()
    sign = SignController()
