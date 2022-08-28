# -*- coding: utf-8 -*-
"""
    Add Keycloak OpenID Connect to your Quart application.
    :copyright: (c) 2022 Kroket Ltd. (https://kroket.io).
    :license: BSD, see LICENSE for more details.
"""


def decorator_parametrized(dec):
    def layer(*args, **kwargs):
        def repl(view_func):
            return dec(args[0], view_func, *args[1:], **kwargs)
        return repl
    return layer
