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

from anchor import auth
from anchor import certificate_ops
from anchor import jsonloader


logger = logging.getLogger(__name__)


class RobotsController(rest.RestController):
    """Serves /robots.txt that disallows search bots."""

    @pecan.expose(content_type="text/plain")
    def get(self):
        return "User-agent: *\nDisallow: /\n"


class SignInstanceController(rest.RestController):
    """Handles POST requests to /v1/sign/ra_name."""

    def __init__(self, ra_name):
        self.ra_name = ra_name

    @pecan.expose(content_type="text/plain")
    def post(self):
        ra_name = self.ra_name

        logger.debug("processing signing request in registration authority %s",
                     ra_name)
        auth_result = auth.validate(ra_name,
                                    pecan.request.POST.get('user'),
                                    pecan.request.POST.get('secret'))
        csr = certificate_ops.parse_csr(pecan.request.POST.get('csr'),
                                        pecan.request.POST.get('encoding'))
        certificate_ops.validate_csr(ra_name, auth_result, csr, pecan.request)

        return certificate_ops.sign(ra_name, csr)


class SignController(rest.RestController):
    @pecan.expose()
    def _lookup(self, ra_name, *remaining):
        if ra_name in jsonloader.registration_authority_names():
            return SignInstanceController(ra_name), remaining
        pecan.abort(404)


class V1Controller(rest.RestController):
    sign = SignController()


class RootController(object):
    robots = RobotsController()
    v1 = V1Controller()
