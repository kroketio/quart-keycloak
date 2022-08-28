"""
This flow is most easiest, it's when your Quart application uses an
external OIDC provider for authentication. The user is redirected to
this OIDC's login page and redirected back to the Quart application,
which after determining/verifying the access token can decide to
consider the user logged in.

1) Log into the Keycloak admin panel: /auth/admin
2) Add a new client (application)
3) Set the correct (redirect) URLs
4) Get the client_id and client_secret
5) Modify `openid_keycloak_config` below
"""

from quart import Quart, url_for, jsonify
from quart_keycloak import Keycloak
from quart_session import Session

app = Quart(__name__)
app.config['SESSION_TYPE'] = 'redis'
Session(app)

openid_keycloak_config = {
    "client_id": "foo",
    "client_secret": "secret",
    "configuration": "https://example.com/auth/realms/master/.well-known/openid-configuration"
}

openid_keycloak = Keycloak(app, **openid_keycloak_config)


@openid_keycloak.after_token()
async def handle_user_login(resp: dict):
    return jsonify(resp['access_token'])


@app.route("/")
async def root():
    login_url_keycloak = url_for(openid_keycloak.endpoint_name_login)

    return f"""
    Login via keycloak: <a href="{login_url_keycloak}">Login via Keycloak</href>
    """


app.run("localhost", port=4000, debug=True)
