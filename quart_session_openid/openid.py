# -*- coding: utf-8 -*-
"""
    Adds OpenID Connect support to your Quart application.
    :copyright: (c) 2021 by Sander.
    :license: BSD, see LICENSE for more details.
"""
import os
import asyncio
import uuid
import json
from urllib.parse import urlparse
from typing import Optional, Coroutine, Any, Callable, Awaitable, List, Union

from packaging import version
import jwt
import aiofiles
from jose import jwt as jose_jwt
from quart import Quart, request, url_for, redirect, session, Response, session

from quart_session_openid import DEFAULT_AUDIENCE, PROVIDER_KEYCLOAK, PROVIDER_AZURE_AD_V1, PROVIDER_AZURE_AD_V2
from quart_session_openid.utils import decorator_parametrized, AzureResource

JWT_LEGACY = version.parse(jwt.__version__) < version.parse("2.0.0")


class OpenID(object):
    """This class is used to add OpenID Connect to one or more Quart
    applications.

        from quart import Quart, url_for, jsonify
        from quart_session_openid import OpenID
        from quart_session import Session

        app = Quart(__name__)
        app.config['SESSION_TYPE'] = 'redis'
        Session(app)

        app = Quart(__name__)
        OpenID(app, client_id=...)

    You may add multiple `OpenID` instances to your Quart app. When you do,
    provide a custom `route_login` and `route_auth` to prevent route overlap.
    """
    def __init__(self,
                 app: Quart,
                 client_id: str,
                 client_secret: str,
                 configuration: str = None,
                 provider: int = PROVIDER_KEYCLOAK,
                 audience: Union[str, AzureResource] = DEFAULT_AUDIENCE,
                 configuration_cache: int = 0,
                 timeout_connect: int = 3,
                 timeout_read: int = 3,
                 scopes: List[str] = None,
                 route_login: str = "/openid/login",
                 route_auth: str = "/openid/auth",
                 user_agent: str = "Quart-OpenID",
                 azure_tenant_id: str = None,
                 key_rotation_interval: int = 3600) -> None:
        """
        :param app: Quart app instance
        :param client_id: public identifier for apps, many OIDC providers
            use something like a 32-character hex string.
        :param client_secret: credentials given by the OIDC provider. If this app is
            a "public" app, then you shouldn't need a secret.
        :param configuration: URL to the OIDC configuration page. This URL usually
            ends with "/.well-known/openid-configuration". Alternatively, you may
            provide an absolute path to the configuration JSON document on your filesystem.
        :param configuration_cache: Cache the configuration page, useful in development.
        :param provider: The "type" of OIDC "flavor" to use, since there are small
            implementation differences between the various OIDC providers (sigh).
            By default it's set to a mode that works well with Keycloak.
            See `quart_openid/__init__.py` for the possible options.
        :param audience: Specifies for **whom** (which application) the token is intended.
            See https://tools.ietf.org/html/rfc7519#section-4.1.3
        :param scopes: List of scopes, by default set to openid, profile, email.
            A scope grants access to a set of "claims", usually embedded inside an
            ID token or calling the userinfo_endpoint (or both).
        :param route_login: The login URL route for this Quart application. You can
            provide your own when you have multiple OpenID instances that would
            otherwise overlap, or simply prefer a customized name.
        :param route_auth: The auth URL route for this Quart application. Visitors redirect
            to this route after completing authentication over at the OIDC provider.
        :param timeout_connect: HTTP connect timeout when communicating with OIDC provider.
        :param timeout_read: HTTP read timeout when communicating with OIDC provider.
        :param user_agent: The HTTP User-Agent request header to use.
        :param azure_tenant_id: If you're using v2.0 of Azure AD Connect, you may
            use this parameter **instead of** supplying `configuration` - the configuration
            URL will be automatically generated using the supplied Tenant ID.
        :param key_rotation_interval: Fetch cert from OIDC every X seconds. Defaults to 1 hour
            https://stackoverflow.com/questions/58330545/azure-active-directory-jwt-public-key-changing
        """
        self.app: Quart = app

        self.client_id: str = client_id
        self.client_secret: str = client_secret

        self.scopes: List[str] = ["openid", "profile", "email"]
        if scopes:
            self.scopes = scopes

        if isinstance(audience, AzureResource):
            audience = audience.app_id
        self._audience: str = audience

        self._azure_tenant_id = azure_tenant_id

        if provider == PROVIDER_AZURE_AD_V1:
            raise Exception("Azure AD v1 not supported, use v2")
        elif provider == PROVIDER_AZURE_AD_V2:
            if not azure_tenant_id:
                raise Exception("Please specify the Azure tenant ID through parameter `azure_tenant_id`")
            url = f"https://login.microsoftonline.com/{self._azure_tenant_id}/v2.0/.well-known/openid-configuration"
            self._openid_configuration_url = f"{url}"
        else:
            self._openid_configuration_url = configuration

        self.provider = provider

        self._openid_configuration: dict = {}
        self._openid_keys: dict = None
        self._openid_keys_rotate: int = key_rotation_interval
        self._openid_keys_task: asyncio.Task = None

        self._cache = None

        self._config_cache_time: int = configuration_cache

        self._route_login_uri: str = route_login
        self._route_auth_uri: str = route_auth

        self._user_agent: str = user_agent
        self._timeout_connect: int = timeout_connect
        self._timeout_read: int = timeout_read

        self._nonce_session_key = "_quart_session_openid_nonce"
        self._nonce = self.provider not in [PROVIDER_AZURE_AD_V1, PROVIDER_AZURE_AD_V2]

        self._fn_after_token = None

        if not self.client_id:
            raise Exception("client_id not set")

        if not self._openid_configuration_url:
            raise Exception("openid_config_url not set")

        if not self._openid_configuration_url.startswith("http"):
            if not os.path.exists(self._openid_configuration_url):
                raise Exception(f"Local file path '{self._openid_configuration_url}' is non-existent")

        if app is not None:
            self.init_app(app)

        @app.before_serving
        async def setup():
            # Read/Fetch OIDC configuration JSON from disk or URL
            self._openid_configuration = await self.fetch_config(self._openid_configuration_url)

            # validate
            for expect in ["token_endpoint", "authorization_endpoint", "jwks_uri"]:
                if expect not in self._openid_configuration:
                    raise Exception(f"Expected key '{expect}' to be present in OpenID configuration JSON; not found.")

            # fetch key
            self._openid_keys = await self.fetch_pubkeys(self._openid_configuration["jwks_uri"])
            self._openid_keys_task = asyncio.create_task(self.fetch_pubkey_loop())

            # internal route handlers
            app.logger.debug(f"OpenID login URL: {self._route_login_uri}")
            app.add_url_rule(self._route_login_uri, self.endpoint_name_login, view_func=self.login)

            app.logger.debug(f"OpenID auth URL: {self._route_auth_uri}")
            app.add_url_rule(self._route_auth_uri, self.endpoint_name_auth, view_func=self.auth)

        @app.after_serving
        async def teardown():
            if self._openid_keys_task:
                if not self._openid_keys_task.cancelled():
                    self._openid_keys_task.cancel()

    def init_app(self, app: Quart) -> None:
        try:
            from quart_session.sessions import SessionInterface
            if not isinstance(app.session_interface, SessionInterface):
                raise Exception("Please setup quart-session before initializing quart-openid.")
        except ImportError as ex:
            raise Exception("quart-session missing; `pip install quart-session`")

        self.app = app
        self._cache = app.session_interface

    async def fetch_config(self, url: str) -> dict:
        """
        :param url: URL or absolute path to the OIDC configuration document
        :return: OpenID configuration dict
        """
        use_cache = self._config_cache_time > 0 and url.startswith("http")
        if use_cache:
            doc = await self._cache.get(key=self._config_cache_key)
            if doc:
                return json.loads(doc)

        try:
            doc = await self.json_get(url)
            if not doc:
                raise Exception(f"empty document")
        except Exception as ex:
            raise Exception(f"Could not fetch OpenID configuration "
                            f"JSON from {url} - {ex}")

        if use_cache:
            await self._cache.set(
                key=self._config_cache_key,
                value=json.dumps(doc),
                expiry=self._config_cache_time)
        return doc

    async def fetch_pubkeys(self, url: str) -> List[dict]:
        """
        :param url: the URL to the OpenID pubkey configuration file
        :return: list of pubkeys
        """
        use_cache = self._config_cache_time > 0
        if use_cache:
            doc = await self._cache.get(key=self._jwks_cache_key)
            if doc:
                return json.loads(doc)

        try:
            doc = await self.json_get(url)
            if not doc:
                raise Exception(f"empty document")
            if "keys" not in doc:
                raise Exception("missing `keys` attribute.")
        except Exception as ex:
            raise Exception(f"Could not fetch certs from {url} - {ex}")

        if use_cache:
            await self._cache.set(
                key=self._jwks_cache_key,
                value=json.dumps(doc),
                expiry=self._config_cache_time)
        return doc["keys"]

    async def fetch_pubkey_loop(self):
        """Keeps fetching cert(s) from OIDC provider in a task"""
        jwks_uri = self._openid_configuration["jwks_uri"]
        while True:
            await asyncio.sleep(self._openid_keys_rotate)
            try:
                self._openid_keys = await self.fetch_pubkeys(jwks_uri)
            except Exception as ex:
                self.app.logger.error(f"Key rotate failure; {ex}")

    def login(self, scopes=None) -> redirect:
        """
        Generate login URL and redirect user to OIC login page.
        :param scopes: An alternative List[str] of scopes, which allows
            you to initiate a login for access_token's that have specific
            scope(s). This is useful to "progressively" ask the user for consent
            throughout the web application, i.e: upon login you might only need
            to read the user profile for the username and email, and later in the
            application you require more access from the user. The user will be
            redirected to the OIDC provider, which will ask for additional consent.

            @app.route("/login/custom")
            async def login_custom():
                scopes = ["Team.ReadBasic.All", "user.read", "openid",
                          "offline_access", "email", "profile"]
                return openid_microsoft.login(scopes=scopes)
        """
        if not self.client_secret:
            raise Exception("client_secret required to initiate confidential flow.")
        if not self._fn_after_token:
            raise Exception("`@openid.after_token()` callback missing, please "
                            "define a token handler.")

        nonce = None
        if self._nonce:
            nonce = uuid.uuid4().hex
            session[self._nonce_session_key] = nonce

        url_auth = self._openid_configuration["authorization_endpoint"]
        scopes = ' '.join(scopes if scopes else self.scopes)

        url = f"{url_auth}?" \
              f"client_id={self.client_id}&" \
              f"redirect_uri={self.redirect_uri}&" \
              f"response_type=code"

        if nonce:
            url += f"&nonce={nonce}"

        if self.provider == PROVIDER_KEYCLOAK:
            # for some reason Keycloak does not accept multiple
            # values for the `scope` GET arg. Instead we'll
            # use `scopes`. confused.jpg
            url += f"&scopes={scopes}"
        else:
            url += f"&scope={scopes}"

        self.app.logger.debug(f"login redirection to {url}")
        return redirect(url)

    async def auth(self):
        if not self.client_secret:
            raise Exception("client_secret required to initiate confidential flow.")

        if "error" in request.args:
            error = request.args["error"]
            description = request.args.get("error_description", "")
            self.app.logger.error(f"redirect error '{error}' {description}")
            return f"{error}, check logs", 500

        for expect in ["code", "session_state"]:
            if expect not in request.args:
                msg = f"Missing '{expect}' argument on"
                raise Exception(msg)

        # with the authorization code we can fetch an access token
        url = self._openid_configuration["token_endpoint"]
        data = {
            "grant_type": "authorization_code",
            "code": request.args["code"],
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        try:
            resp = await self.json_post(url, data=data, raise_status=False, json=False)
            if "error" in resp:
                raise Exception(f"{resp['error']}: {resp.get('error_description', 'unknown error')}")
        except Exception as ex:
            raise Exception(ex)

        access_token = resp.get("access_token", "")
        token_type = resp.get("token_type", "").lower()

        if token_type != "bearer":
            raise Exception("unsupported token type")
        if not access_token:
            self.app.logger.error(f"Access token not in response for {url}")
            raise Exception("unknown error, check logs")

        # verify jwt header
        access_token_header = jwt.get_unverified_header(access_token)
        for expect in ["kid", "alg"]:
            if expect not in access_token_header:
                raise Exception(f"Invalid JWT header for token {access_token}")

        # verify we actually have the key id
        key_id = access_token_header['kid']
        if key_id not in self._get_keyids:
            # unknown kid, attempt to refresh OIDC keys
            keys = await self.fetch_pubkeys(self._openid_configuration['jwks_uri'])
            if not keys or key_id not in [k['kid'] for k in keys]:
                raise Exception("Could not validate token; unknown kid")
            self._openid_keys = keys

        if self._nonce:
            nonce = session.get(self._nonce_session_key)
            for token in [v for k, v in resp.items() if k.endswith("_token")]:
                token_decoded = OpenID.decode_token(token)
                if "nonce" not in token_decoded:
                    raise Exception(f"Missing nonce in {token}")
                if token_decoded['nonce'] != nonce:
                    raise Exception("Bad nonce")
            session.pop(self._nonce_session_key)

        return await self._fn_after_token(resp)

    async def user_info(self, access_token):
        import aiohttp
        url = self._openid_configuration["userinfo_endpoint"]
        _headers = {
            "User-Agent": self._user_agent,
            "Authorization": f"Bearer {access_token}"
        }
        async with aiohttp.ClientSession(
                headers=_headers,
                conn_timeout=self._timeout_connect,
                read_timeout=self._timeout_read) as session:
            async with session.get(url) as resp:
                print("Status:", resp.status)
                print("Content-type:", resp.headers.get('content-type'))
                return await resp.json()

    async def json_get(self, url: str, token: str = None, raise_status: bool = True) -> dict:
        import aiohttp
        _headers = {"User-Agent": self._user_agent}
        if token:
            _headers["Authorization"] = f"Bearer {token}"

        async with aiohttp.ClientSession(
                headers=_headers,
                conn_timeout=self._timeout_connect,
                read_timeout=self._timeout_read) as session:
            async with session.get(url) as resp:
                if raise_status:
                    resp.raise_for_status()
                return await resp.json()

    async def json_post(self, url: str, token: str = None, data: dict = None, raise_status: bool = True, json: bool = True) -> dict:
        import aiohttp
        _headers = {"User-Agent": self._user_agent}
        if token:
            _headers["Authorization"] = f"Bearer {token}"

        async with aiohttp.ClientSession(
                headers=_headers,
                conn_timeout=self._timeout_connect,
                read_timeout=self._timeout_read) as session:
            _data = {"json": data} if json else {"data": data}
            async with session.post(url, **_data) as resp:
                if raise_status:
                    resp.raise_for_status()
                return await resp.json()

    def verify_token(self, token: str, algorithms: Union[List[str], str] = 'RS256', audience: str = 'account') -> dict:
        """
        Verifies RS256 token with known pubkey(s)
        :param token: JWS
        :param algorithms: algorithms (str or list): Valid algorithms that should be used to verify the JWS.
        :param audience:
        :return: the decoded/verified token
        """
        try:
            payload = jose_jwt.decode(token, self._openid_keys, algorithms=algorithms, audience=audience)
            return payload
        except Exception as ex:
            msg = f"Invalid payload for token: {token} - {ex}"
            self.app.logger.error(msg)
            raise

    @staticmethod
    def decode_token(token: str):
        """Return data inside JWT - important: does *not* verify the token"""
        if JWT_LEGACY:
            return jwt.decode(token, verify=False)
        return jwt.decode(token, options={"verify_signature": False})

    @property
    def base_url(self):
        headers = {k.lower(): v for k, v in dict(request.headers).items()}
        port = None
        spl = urlparse(request.base_url)
        scheme = spl[0]
        if "x-forwarded-proto" in headers:
            scheme = headers["x-forwarded-proto"]
        if "x-forwarded-port" in headers:
            port = int(headers['x-forwarded-port'])
        port = f":{port}" if isinstance(port, int) else ""
        return f"{scheme}://{request.host}{port}"

    @property
    def redirect_uri(self):
        return f"{self.base_url}{self._route_auth_uri}"

    @property
    def endpoint_name_login(self) -> str:
        """Endpoint names are dynamically generated using `client_id`, use this function if you
        want to use an endpoint in `quart.url_for`, e.g:

            return redirect(url_for(openid.login_endpoint_name))
        """
        return f"quart_openid_login_{self.client_id}"

    @property
    def endpoint_name_auth(self) -> str:
        return f"quart_openid_auth_{self.client_id}"

    @property
    def _config_cache_key(self):
        return f"openid_config_cache_{self.client_id}"

    @property
    def _jwks_cache_key(self):
        return f"openid_jwks_cache_{self.client_id}"

    @property
    def _get_keyids(self):
        return [k['kid'] for k in self._openid_keys]

    @decorator_parametrized
    def after_token(self, view_func, *args, **kwargs):
        self._fn_after_token = view_func

    async def _json_read(self, path: str):
        async with aiofiles.open(path, mode='r') as f:
            return json.loads(await f.read())
