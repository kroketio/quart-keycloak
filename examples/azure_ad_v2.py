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
from quart_session_openid import OpenID, AAD_GRAPH_API, PROVIDER_AZURE_AD_V2, MICROSOFT_GRAPH
from quart_session import Session

app = Quart(__name__)
app.config['SESSION_TYPE'] = 'redis'
Session(app)

# See Azure AD admin panel for more Graph API permissions,
# for example the scopes could be:
# ["user.read", "offline_access", "email", "profile", "openid"]

openid_microsoft_config = {
    "client_id": "dec28b22-11bc-4444-66d7-a355ebeb02e6",
    "client_secret": "foo",
    "route_login": "/user/login/ms",
    "route_auth": "/user/login/ms/auth",
    "audience": [AAD_GRAPH_API],
    "provider": PROVIDER_AZURE_AD_V2,
    "azure_tenant_id": "ac33c1db-7214-4e28-20e8-4b4d7581332c",
    "scopes": ["email", "profile", "openid"]
}

openid_microsoft = OpenID(app, **openid_microsoft_config)


@openid_microsoft.after_token()
async def after_ms_auth(resp: dict):
    # We can grab user information from the `id_token`, which needs to be verified.
    # https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
    id_token = resp['id_token']
    id_token_decoded = openid_microsoft.verify_token(id_token, audience=openid_microsoft.client_id)

    # The refresh token is present when the `offline_access` scope was supplied
    # refresh_token = resp.get("refresh_token")

    # The access token can be used to call an API. See the `aud` claim to
    # see who the target API for this access token is. Note that this access_token
    # cannot be verified if the `aud` claim is not us.
    access_token = resp.get("access_token")
    access_token_decoded = OpenID.decode_token(access_token)

    # Get our profile
    graph_url = f"{MICROSOFT_GRAPH.uri}/v1.0"
    me = await openid_microsoft.json_get(f"{graph_url}/me/", token=access_token)

    # Get the Microsoft Teams this user is a member of (requires the `Team.ReadBasic.All` scope).
    # user_id = access_token_decoded["oid"]
    # teams = await openid_microsoft.json_get(f"{graph_url}/users/{user_id}/joinedTeams", token=access_token)
    # for team in teams.get('value', []):
    #     print(team['displayName'])

    # @TO-DO: mark the user as "logged in" - do some database stuff, etc.
    return jsonify({
        "id_token": id_token_decoded,
        "access_token": access_token_decoded,
        "me": me
    })


@app.route("/")
async def root():
    login_url_microsoft = url_for(openid_microsoft.endpoint_name_login)

    return f"""
    Login via Azure AD: <a href="{login_url_microsoft}">Login via Microsoft Azure AD</href>
    """


app.run("localhost", port=4000, debug=True)