"""
1) Login into Azure AD portal; https://portal.azure.com/#home
2) Go to Azure Active Directory, note the Tenant ID
3) Go to App Registrations
4) Register app, obtain client_id
5) Go to "Certificates & Secrets", obtain client_secret
6) Go to "Authentication" and setup Redirect URIs
7) Optionally go to API permissions to authorize API calls.
"""
from quart import Quart, url_for, jsonify
from quart_session_openid import OpenID, AAD_GRAPH_API, PROVIDER_AZURE_AD_V2
from quart_session import Session

app = Quart(__name__)
app.config['SESSION_TYPE'] = 'redis'
Session(app)


openid_microsoft_config = {
    "client_id": "dec28b22-11bc-4444-66d7-a355ebeb02e6",
    "client_secret": "foo",
    "route_login": "/user/login/ms",
    "route_auth": "/user/login/ms/auth",
    "scopes": ["email", "profile", "openid"],
    "audience": [AAD_GRAPH_API],
    "provider": PROVIDER_AZURE_AD_V2,
    "azure_tenant_id": "ac33c1db-7214-4e28-20e8-4b4d7581332c"
}

openid_microsoft = OpenID(app, **openid_microsoft_config)


@openid_microsoft.after_token()
async def after_ms_auth(access_token: dict):
    # @TODO: token verification not possible
    return jsonify(access_token)


@app.route("/")
async def root():
    login_url_microsoft = url_for(openid_microsoft.endpoint_name_login)

    return f"""
    Login via Azure AD: <a href="{login_url_microsoft}">Login via Microsoft Azure AD</href>
    """


app.run("localhost", port=4000, debug=True)