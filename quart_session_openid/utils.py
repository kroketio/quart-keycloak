# -*- coding: utf-8 -*-
"""
    Adds OpenID Connect support to your Quart application.
    :copyright: (c) 2021 by Sander.
    :license: BSD, see LICENSE for more details.
"""


def decorator_parametrized(dec):
    def layer(*args, **kwargs):
        def repl(view_func):
            return dec(args[0], view_func, *args[1:], **kwargs)
        return repl
    return layer


class AzureResource:
    def __init__(self, name: str, uri: str, app_id: str):
        self.name = name
        self.uri = uri
        self.app_id = app_id

    def __eq__(self, other: str):
        return other == self.app_id
