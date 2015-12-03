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

import logging

import pecan
from pecan import rest
from webob import exc as http_status

from anchor import audit
from anchor import auth
from anchor import certificate_ops
from anchor import jsonloader


logger = logging.getLogger(__name__)


class RobotsController(rest.RestController):
    """Serves /robots.txt that disallows search bots."""

    @pecan.expose(content_type="text/plain")
    def get(self):
        return "User-agent: *\nDisallow: /\n"


class GenericInstanceController(rest.RestController):
    """Handles requests to /xxx/ra_name."""
    def __init__(self, ra_name):
        self.ra_name = ra_name


class SignInstanceController(GenericInstanceController):
    """Handles POST requests to /sign/instance."""
    @pecan.expose(content_type="text/plain")
    def post(self):
        ra_name = self.ra_name

        logger.debug("processing signing request in registration authority %s",
                     ra_name)
        try:
            auth_result = auth.validate(ra_name,
                                        pecan.request.POST.get('user'),
                                        pecan.request.POST.get('secret'))
            audit.emit_auth_event(ra_name, pecan.request.POST.get('user'),
                                  auth_result)
        except http_status.HTTPUnauthorized:
            audit.emit_auth_event(ra_name, pecan.request.POST.get('user'),
                                  None)
            raise

        try:
            csr = certificate_ops.parse_csr(pecan.request.POST.get('csr'),
                                            pecan.request.POST.get('encoding'))
            certificate_ops.validate_csr(ra_name, auth_result, csr,
                                         pecan.request)
            csr = certificate_ops.fixup_csr(ra_name, csr, pecan.request)

            cert, fingerprint = certificate_ops.dispatch_sign(ra_name, csr)
            audit.emit_signing_event(ra_name, pecan.request.POST.get('user'),
                                     auth_result, fingerprint=fingerprint)
        except Exception:
            audit.emit_signing_event(ra_name, pecan.request.POST.get('user'),
                                     auth_result)
            raise
        return cert


class CAInstanceController(GenericInstanceController):
    """Handles POST requests to /ca/ra_name."""
    @pecan.expose(content_type="text/plain")
    def get(self):
        ra_name = self.ra_name

        return certificate_ops.get_ca(ra_name)


class RAController(rest.RestController):
    def __init__(self, subcontroller):
        self._subcontroller = subcontroller

    @pecan.expose()
    def _lookup(self, ra_name, *remaining):
        if ra_name in jsonloader.registration_authority_names():
            return self._subcontroller(ra_name), remaining
        pecan.abort(404)


class V1Controller(rest.RestController):
    sign = RAController(SignInstanceController)
    ca = RAController(CAInstanceController)


class RootController(object):
    robots = RobotsController()
    v1 = V1Controller()
