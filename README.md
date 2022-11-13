**Warning: this project is deprecated and replaced by https://pypi.org/project/Quart-Keycloak/**

# Quart-Session-OpenID

Adds OpenID Connect support to your Quart application.

Supports the following OAuth2 flows:

- Confidential - Authorization code flow
- Public - Implicit grant (SPA: VueJS, Angular, React, etc)

This extension assumes that the OIDC provider is [Keycloak](https://www.keycloak.org/),
unless specified otherwise. Known working OIDC providers:

- Keycloak
- Azure AD Connect 2.0

## Quick start

```text
$ pipenv install quart-session-openid
$ pip install quart-session-openid
```

Minimal example to authenticate via an external OIDC provider, Keycloak in this case:

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

    # do some database and session stuff here (like add user to the database)

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

For the implicit grant flow (single page applications), Javascript is responsible
for authentication against a OIDC in order to fetch access/refresh tokens
that it presents to the backend (Quart) via a Bearer token. The backend needs to
verify incoming Bearer tokens. See `examples/implicit_grant.py` for an example.

## Custom scopes

For user registration/login you might only need to
read the user profile for the username and email. Later in the
application you might require more access from the user. For this
reason, you may override the scopes to generate a custom login route.

```python3
@app.route("/login/custom")
async def login_custom():
    scopes = ["Team.ReadBasic.All", "user.read", "openid",
              "offline_access", "email", "profile"]
    return openid_microsoft.login(scopes=scopes)
```

This is useful to progressively ask the user for consent throughout the web application.

## Multiple OIDC providers

You may create multiple `OpenID(app, **settings)` instances, allowing for
multiple OIDC providers. Make sure to provide custom route handlers
for the login and auth URL route (`route_login` and `route_auth`).
