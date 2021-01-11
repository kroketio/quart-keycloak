# Quart-Session-OpenID

Adds OpenID Connect support to your Quart application.

Supports the following OAuth2 flows:

- Confidential - Authorization code flow
- Public - Implicit grant (SPA: VueJS, Angular, React, etc)

This extension assumes that the OIDC provider is [Keycloak](https://www.keycloak.org/),
unless specified otherwise. Known working OIDC providers:

- Keycloak
- Azure AD Connect 2.0

[quart-session](https://github.com/sferdi0/quart-session) is a requirement - used for its session management capabilities via Redis et. al.

# Example

Minimal example to login via external OIDC provider (Keycloak).

```python3
from quart import Quart, url_for, jsonify
from quart_session_openid import OpenID
from quart_session import Session

app = Quart(__name__)
app.config['SESSION_TYPE'] = 'redis'
Session(app)

openid_keycloak_config = {
    "client_id": "foobar",
    "client_secret": "secret",
    "configuration": "https://example.com/auth/realms/master/.well-known/openid-configuration"
}

openid_keycloak = OpenID(app, **openid_keycloak_config)


@openid_keycloak.after_token()
async def handle_user_login(resp: dict):
    # incoming token(s) are *NOT* validated, it is *imperative*
    # that you validate the signature like this:
    access_token_decoded = openid_keycloak.verify_token(resp["access_token"])

    # @TO-DO: mark the user as "logged in" - do some database stuff, etc.

    # optionally call the userinfo endpoint
    user = await openid_keycloak.user_info(access_token)
    return jsonify(user)


@app.route("/")
async def root():
    login_url_keycloak = url_for(openid_keycloak.endpoint_name_login)

    return f"""
    Login via keycloak: <a href="{login_url_keycloak}">Login via Keycloak</href>
    """


app.run("localhost", port=4000, debug=True)
```

## Example 2: Azure AD

Azure AD supports OpenID Connect and as such anyone with a Microsoft
Office 365 account (or otherwise an account in Azure AD) could login into
your web application.

See `examples/azure_ad_v2.py` for an example.

## Example 3: Implicit grant

For the implicit grant (single page applications), Javascript is responsible
for authentication against a OIDC in order to fetch access/refresh tokens
that it presents to the backend (Quart).

The backend needs to verify incoming Bearer tokens. You can use
`OpenID.verify_token()` for that.

Example decorator:

```python3
from functools import wraps
from quart import abort, current_app, g


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
    print(g.jwt)

    products = ["foo", "bar"]
    return jsonify(products)
```

## Multiple OIDC providers

You may create multiple `OpenID(app, **settings)` instances, allowing for
multiple OIDC providers. Make sure to provide custom route handlers
for the login and auth URL route (`route_login` and `route_auth`).
