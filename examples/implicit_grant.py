"""
Simple example of a decorator you may attach
to view functions that validates incoming Bearer
tokens. It's dirty but hey, perhaps it serves as
inspiration for your own implementation.
"""
from functools import wraps
from quart import Quart, url_for, jsonify, current_app, g, request, abort
from quart_session_openid import OpenID
from quart_session import Session

app = Quart(__name__)
app.config['SESSION_TYPE'] = 'redis'
Session(app)

openid_keycloak_config = {
    "client_id": "foo",
    "client_secret": "secret",
    "configuration": "https://example.com/auth/realms/master/.well-known/openid-configuration"
}

openid_keycloak = OpenID(app, **openid_keycloak_config)


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


@app.route("/")
async def root():
    login_url_keycloak = url_for(openid_keycloak.endpoint_name_login)

    return f"""
    Login via keycloak: <a href="{login_url_keycloak}">Login via Keycloak</href><br>
    <a href="{url_for('api_products_get')}">protected route</a>
    """

app.run("localhost", port=4000, debug=True)