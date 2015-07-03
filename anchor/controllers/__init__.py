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


class GenericInstanceController(rest.RestController):
    """Handles requests to /xxx/instance."""
    def __init__(self, instance):
        self.instance = instance


class SignInstanceController(GenericInstanceController):
    """Handles POST requests to /sign/instance."""
    @pecan.expose(content_type="text/plain")
    def post(self):
        instance = self.instance

        logger.debug("processing signing request in instance %s", instance)
        auth_result = auth.validate(instance,
                                    pecan.request.POST.get('user'),
                                    pecan.request.POST.get('secret'))
        csr = certificate_ops.parse_csr(pecan.request.POST.get('csr'),
                                        pecan.request.POST.get('encoding'))
        certificate_ops.validate_csr(instance, auth_result, csr, pecan.request)

        return certificate_ops.sign(instance, csr)


class CAInstanceController(GenericInstanceController):
    """Handles POST requests to /ca/instance."""
    @pecan.expose(content_type="text/plain")
    def post(self):
        instance = self.instance

        auth.validate(instance,
                      pecan.request.POST.get('user'),
                      pecan.request.POST.get('secret'))

        return certificate_ops.get_ca(instance)


class InstanceController(rest.RestController):
    def __init__(self, subcontroller):
        self._subcontroller = subcontroller

    @pecan.expose()
    def _lookup(self, instance, *remaining):
        if instance in jsonloader.instance_names():
            return self._subcontroller(instance), remaining
        pecan.abort(404)


class V1Controller(rest.RestController):
    sign = InstanceController(SignInstanceController)
    ca = InstanceController(CAInstanceController)


class RootController(object):
    robots = RobotsController()
    v1 = V1Controller()
