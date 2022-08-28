# -*- coding: utf-8 -*-
"""
    Add Keycloak OpenID Connect to your Quart application.
    :copyright: (c) 2022 Kroket Ltd. (https://kroket.io).
    :license: BSD, see LICENSE for more details.
"""
DEFAULT_AUDIENCE = "account"

from quart_keycloak.openid import Keycloak, KeycloakAuthToken, KeycloakLogoutRequest
