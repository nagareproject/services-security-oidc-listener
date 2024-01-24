# Encoding: utf-8

# --
# Copyright (c) 2008-2024 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

from nagare.services import plugin
from nagare.sessions import common


class Service(plugin.Plugin):
    LOAD_PRIORITY = common.SessionsSelection.LOAD_PRIORITY - 1

    def __init__(self, name, dist, services_service, **config):
        services_service(super(Service, self).__init__, name, dist, **config)
        self.oidc_services = {}

    def register_service(self, ident, oidc_service):
        self.oidc_services[ident] = oidc_service

    def handle_request(self, chain, request, **params):
        code = request.params.get('code')
        state = request.params.get('state')

        if state and code:
            self.logger.debug('Authentication response: %s / %s', state, code)
            if state.count('#') != 2:
                raise ValueError('Invalid authentication response: %s / %s' % (state, code))

            oidc_service_ident = state.split('#')[1]
            oidc_service = self.oidc_services.get(oidc_service_ident)
            if oidc_service is not None:
                is_valid, session_id, state_id = oidc_service.is_auth_response(request)[:3]
                if is_valid:
                    params['session_id'] = session_id
                    params['state_id'] = state_id

                    request.is_authenticated = True

        return chain.next(request=request, **params)
