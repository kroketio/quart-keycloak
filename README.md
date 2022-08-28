# Quart-Keycloak

Add [Keycloak](https://www.keycloak.org/) OpenID Connect to your Quart application

- [Quick start](#)
- [Terminology](#)
  - `OIDC`: OpenID Connect - A layer built on top of the OAuth 2.0 protocol
  - `IdP`: The identity provider, also sometimes called `OP` (OpenID Provider). In our case; Keycloak.
  - `Client`: the application that interacts with a `IdP` (Keycloak), in our case Quart. Sometimes also called `Relying Party`.
  - Client Types: 
    - `confidential` - Clients **capable** of maintaining the confidentiality of their credentials, so backend applications made in PHP, Perl, Python, etc. The example in "[Quick Start](#QuickStart) is an example of a confidential client.
    - `public` - Clients **incapable** of maintaining the confidentiality of their credentials: VueJS, React, Angular. 
  - `User Agent`: the end-user, often times 'the browser'.
- [Logout](#)
  - [](#)
  - [RP-Initiated Logout](#)
  - [Handling BackChannel Logout's](#)
- [FAQ](#)
  - [Multiple IdP's](#)
  - [Using different IdP's](#)

## Quick start

```text
$ pip install quart-keycloak
or
$ pipenv install quart-keycloak
```

Minimal example:

```python3
from quart import Quart, url_for, jsonify, session, redirect
from quart_session import Session
from quart_keycloak import Keycloak, KeycloakAuthToken, KeycloakBackChannelLogout

app = Quart(__name__)
app.secret_key = 'changeme'
app.config['SESSION_TYPE'] = 'redis'
Session(app)

openid_keycloak_config = {
    "client_id": "",
    "client_secret": "",
    "configuration": "https://host/realms/master/.well-known/openid-configuration"
}

keycloak = Keycloak(app, **openid_keycloak_config)


@keycloak.after_login()
async def handle_user_login(auth_token: KeycloakAuthToken):
    # optionally call the userinfo endpoint for more info
    user = await keycloak.user_info(auth_token.access_token)

    # set session
    session['auth_token'] = auth_token
    return redirect(url_for('root'))

@app.route("/logout")
async def logout():
    # route that clears the session
    session.clear()
    return redirect(url_for('root'))


@app.route("/")
async def root():
    # redirect the user after logout
    logout_url = url_for('logout', _external=True)

    # the login URL
    login_url_keycloak = url_for(keycloak.endpoint_name_login)

    # the logout URL, `redirect_uri` is required. `state` is optional.
    logout_url_keycloak = url_for(keycloak.endpoint_name_logout, redirect_uri=logout_url, state='bla')

    return f"""
    <b>token:</b> {session.get('auth_token')}<br><hr>
    Login via keycloak: <a href="{login_url_keycloak}">Login via Keycloak</a><br>
    Logout via keycloak: <a href="{logout_url_keycloak}">Logout via Keycloak</a>
    """


app.run("localhost", port=2700, debug=True, use_reloader=False)
```

In the above example, [quart-session](https://github.com/kroketio/quart-session/) is 
used to provide a session interface via Redis. You don't have to use this extension, however, 
this is encouraged, as Quart's default is to save the session client-side which is more difficult to invalidate when you are using the OIDC feature [backchannel logout]().

## Terminology


## How to handle logouts

## Backchannel logout


## Multiple OIDC providers

You may create multiple `Keycloak(app, **settings)` instances, allowing for
multiple OIDC providers. Make sure to provide custom route handlers
for the login and auth URL route (`route_login` and `route_auth`).
