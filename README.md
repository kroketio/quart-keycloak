# Quart-Session-OpenID

Adds OpenID Connect support to your Quart application.

Supports for the following OAuth2 flows:

- Confidential - Authorization code flow
- Public - Implicit grant (SPA: VueJS, Angular, React, etc)

This extension assumes that the OIDC provider is [Keycloak](https://www.keycloak.org/),
unless specified otherwise. Known working OIDC providers:

- Keycloak
- Azure AD Connect 2.0

**Still in development**

# Examples
## Confidential flow

This flow is most easiest, it's when your Quart application uses an
external OIDC provider for authentication. The user is redirected to
this OIDC's login page and redirected back to the Quart application,
which after determining/verifying the access token can decide to
consider the user logged in.

```python
from quart import Quart, url_for, jsonify
from quart_session_openid import OpenID
from quart_session import Session

app = Quart(__name__)

# https://github.com/sferdi0/quart-session/#redis-support
app.config['SESSION_TYPE'] = 'redis'
Session(app)

openid_settings = {
    "client_id": "myapp",
    "client_secret": "...",
    "configuration": "https://example.com/auth/realms/master/.well-known/openid-configuration"
}

openid_keycloak = OpenID(app, **openid_settings)

@openid_keycloak.after_token()
async def handle_user_login(resp: dict):
    openid_keycloak.verify_token(token=resp['access_token'])
    return jsonify(resp)

@app.route("/")
async def root():
    login_url_keycloak = url_for(openid_keycloak.endpoint_name_login)

    return f"""
    <h1>Keycloak example</h1>
    <a href="{login_url_keycloak}">Login via Keycloak</href>
    """

app.run("localhost", port=4000, debug=True)
```

## Confidential flow with Azure AD Connect 2.0

If you would like to allow users with a Microsoft Office 365
account (which uses Azure AD in the background) to authenticate
inside your Quart application, use the following `openid_settings`.

```python3
from quart_session_openid import OpenID, AAD_GRAPH_API, PROVIDER_AZURE_AD_V2

openid_settings = {
    "client_id": "bea33b21-57dd-4257-58d7-c365aaab08e6",
    "client_secret": "...",
    "azure_tenant_id": "b569f29e-b003-5add-b6f0-44fa8132d54a",
    "provider": PROVIDER_AZURE_AD_V2,
    "scopes": ["email", "profile", "openid"],
    "audiences": [AAD_GRAPH_API]
}
```

After receiving an `access_token` in the callback handler you may
query the API for which this token is intended (see also `audience`).
Please note that for this reason the token cannot be verified as
it's not meant to be consumed by us (You can however call the
userinfo endpoint and determine if the token is valid).

## Implicit grant

When the front-end of your application is a single page application (SPA), and Javascript is
doing the authentication against a OIDC in order to fetch access/refresh tokens then your SPA
is a public client and the flow is called "implicit grant". Often times, in this setup, the back-end
application (Quart) is a REST API.

For authentication and authorization purposes, the back-end API needs to verify incoming access
tokens. You can use `OpenID.verify_token()` for that. Here is an example decorator:

```python3
from functools import wraps
from quart import abort, current_app, g

openid_settings = {
    "client_id": "myapp",
    "client_secret": "...",
    "configuration": "https://example.com/auth/realms/master/.well-known/openid-configuration"
}

openid_keycloak = OpenID(app, **openid_settings)


def verify_access_token(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth.startswith("Bearer "):
            abort(401)
        token = auth.split(" ", 1)[0]
        try:
            g.jwt = openid_keycloak.verify_token(token=token, audience="account")
        except:
            abort(401)

        return await func(*args, **kwargs)
    return wrapper

@verify_access_token
@app.route("/api/2/products/")
async def api_products_get():
    print(g.jwt)  # holds verified user information from the access token

    products = ["foo", "bar"]
    return jsonify(products)
```

## Multiple OIDC providers

```python3
keycloak_settings = {
    "client_id": "myapp",
    "client_secret": "...",
    "configuration": "https://example.com/auth/realms/master/.well-known/openid-configuration",
    "route_login": "/user/login/keycloak",
    "route_auth": "/user/login/keycloak/auth"
}

azure_settings = {
    "client_id": "bea33b21-57dd-4257-58d7-c365aaab08e6",
    "client_secret": "...",
    "azure_tenant_id": "b569f29e-b003-5add-b6f0-44fa8132d54a",
    "provider": PROVIDER_AZURE_AD_V2,
    "scopes": ["email", "profile", "openid"],
    "audiences": [AAD_GRAPH_API],
    "route_login": "/user/login/ms",
    "route_auth": "/user/login/ms/auth"
}

openid_azure = OpenID(app, **azure_settings)
openid_keycloak = OpenID(app, **keycloak_settings)

@openid_keycloak.after_token()
async def handle_user_login_keycloak(resp: dict):
    openid_keycloak.verify_token(token=resp['access_token'])
    return jsonify(resp)

@openid_azure.after_token()
async def handle_user_login_azure(resp: dict):
    # access_tokens cannot be verified because the token
    # is not meant for us, but rather for another API, such
    # as the Microsoft Graph API.
    return jsonify(resp)

@app.route("/")
async def root():
    login_url_keycloak = url_for(openid_keycloak.endpoint_name_login)
    login_url_azure = url_for(openid_azure.endpoint_name_login)

    return f"""
    <a href="{login_url_azure}">Login via Azure AD Connect v2</href>
    <a href="{login_url_keycloak}">Login via Keycloak</href>
    """
```
