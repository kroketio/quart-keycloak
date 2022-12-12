# Quart-Keycloak

Add [Keycloak](https://www.keycloak.org/) (OpenID Connect) to your Quart application.

### TOC

- [Quick start](#quick-start)
- [Compatibility](#compatibility)
- [Session](#backend-sessions)
- [Logout](#logout)
  - [Handling logout 'events'](#handling-logout-events)
- [FAQ](#faq)
  - [Multiple keycloaks](#multiple-keycloaks)
  - [HTTP Proxy](#http-proxy)
  - [Using different IdPs](#using-different-idps)
  - [Will you support OIDC feature $x?](#will-you-support-oidc-feature-x)
  - [Common errors](#common-errors)
- [Terminology](#terminology)

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
from quart_keycloak import Keycloak, KeycloakAuthToken, KeycloakLogoutRequest

app = Quart(__name__)
app.secret_key = 'changeme'
app.config['SESSION_TYPE'] = 'redis'
Session(app)

openid_keycloak_config = {
    "client_id": "",
    "client_secret": "",
    "configuration": "https://example.com/realms/master/.well-known/openid-configuration"
}

keycloak = Keycloak(app, **openid_keycloak_config)


@keycloak.after_login()
async def handle_user_login(auth_token: KeycloakAuthToken):
    user = await keycloak.user_info(auth_token.access_token)  # optionally call the userinfo endpoint for more info

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

## Compatibility

This extension is known to work on the following IdPs:

- Keycloak 12 till 19
- Keycloak 10 (limited features)

And (probably) also (but not officially supported):

- Okta
- Azure AD (OIDC)

When running Keycloak 10 you'll need to enable 'legacy' mode by passing 
the parameter `legacy=True` to the Keycloak constructor:

```python3
keycloak = Keycloak(app, legacy=True, client_id=...)
```

Note that the OpenID configuration URL changed between the Keycloak versions:

- Keycloak 10: `https://example.com/auth/realms/master/.well-known/openid-configuration`
- Keycloak 19: `https://example.com/realms/master/.well-known/openid-configuration`

## Backend Sessions

In the [Quick Start](#quick-start) example above, the extension
[quart-session](https://github.com/kroketio/quart-session/) is leveraged to provide Quart a backend session 
interface via Redis. This is strongly recommended as the default session storage is a client-side 
cookie which is difficult to invalidate. For some OIDC features we need to invalidate sessions.

## Login

Generate a login URL and redirect the user. 

```python3
from quart import url_for, redirect

@app.route('/login')
async def login():
  login_url_keycloak = url_for(keycloak.endpoint_name_login)
  return redirect(login_url_keycloak)
```

Use decorator `@keycloak.after_login()` to setup a session within Quart after the user logged in.

```python3
from quart import session, redirect, url_for
from quart_keycloak import KeycloakAuthToken

@keycloak.after_login()
async def handle_user_login(auth_token: KeycloakAuthToken):
    session['auth_token'] = auth_token
    return redirect(url_for('some_other_place'))
```

## Logout

Generate a logout URL and redirect the user. You will need to provide `redirect_uri` to specify 
the return URL (optionally you may pass a `state` parameter). It makes sense to redirect the user back 
to a URL that clears the session on the Quart side, for example `/after_logout`.

In short:

1. Redirect to `keycloak.endpoint_name_logout` (by default `/openid/logout`)
2. Which redirects to Keycloak
3. and Keycloak redirects back to Quart - to the `redirect_uri` that you passed in step 1.

```python3
from quart import session, redirect, url_for

@app.route("/logout")
async def logout():
    logout_url_keycloak = url_for(keycloak.endpoint_name_logout, redirect_uri=url_for('after_logout', _external=True))
    return redirect(logout_url_keycloak)

@app.route("/after_logout")
async def after_logout():
    session.clear()
    return redirect(url_for('root'))

@app.route("/")
async def root():
    return "Hello world!"
```

### Handling logout 'events'

Optionally, Keycloak has the ability to send Quart a logout event (called `logout request`) to 
a URL that you provide. This is useful in the situation that a user is (forcefully) logged out of Keycloak 
via the Keycloak web-interface (or perhaps via another application). Quart would need to receive such 
logout event in order to know the session does not exist anymore on the Keycloak side (and invalidate it on the 
Quart side), as this logout request was not initiated by our Quart application.

In the client settings, fill in `Backchannel logout URL` (replace `example.com` with your own) and 
enable the toggle `Backchannel logout session required`. Note that your Quart application will have 
to be reachable by Keycloak, as Keycloak will try to send a HTTP request to this URL upon user logout.

![https://i.imgur.com/6hZXHwt.png](https://i.imgur.com/6hZXHwt.png)

We can pick up this logout request via a decorator:

```python3
from quart_session import SessionInterface
from quart_keycloak import KeycloakLogoutRequest

@keycloak.after_logout_request()
async def handle_logout_request(token: KeycloakLogoutRequest):
    cache: SessionInterface = app.session_interface
    redis_key_id = f"{app.session_interface.key_prefix}{token.sid}"
    await cache.delete(redis_key_id)
    return "OK"
```

Upon receiving a logout request, we'll need to find the right session to clear. Thankfully the incoming `token` 
parameter will contain a `sid` (session ID) that we can use for this - which prevents us from, for example, 
having to loop all available Redis session keys. 

To achieve this, we can make Quart's session identifier the same as Keycloak's session identifier 
so that it is the same during handling of the logout request.

```python3
@keycloak.after_login()
async def handle_user_login(auth_token: KeycloakAuthToken):
    session['auth_token'] = auth_token
    session.sid = auth_token.access_token_d['sid']  # <== here
    return redirect(url_for('root'))
```

If you do not like this approach, you can always create some sort of
mapper that links Keycloak `sid`'s to Quart sessions.

## FAQ

### Multiple keycloak's

It is perfectly fine to use multiple Keycloak instances, just make sure to provide 
custom route handlers for `route_login`, `route_auth`, `route_logout`, and `route_logout_request` else 
the routes start to overlap.

### HTTP Proxy

Quart-Keycloak uses `aiohttp` which has [an option called 'trust_env'](https://docs.aiohttp.org/en/stable/client_reference.html). We can pass this `trust_env` option via the `aiohttp_clientsession_opts` parameter, e.g:


```python3
keycloak = Keycloak(app, aiohttp_clientsession_opts={'trust_env': True})
```

`aiohttp` will now listen to `HTTP_PROXY` and `HTTPS_PROXY` env. variables.

### Using different IdPs

Previously this extension was known as `quart-session-openid` and made an effort to support multiple 
OpenID servers but it turns out that everyone has their own interpretation of the OpenID spec so 
IdPs tended to vary which caused breakage. Even between Keycloak versions there are small (but breaking) 
changes - so it was decided to narrow the scope, rebrand to `quart-keycloak` and focus on modern Keycloak versions.

### Will you support OIDC feature $x?

The OpenID specification is rather large (and confusing) and this extension tries to abstract the 
complicated parts away and makes the fair assumption that your web application 
wants some basic OIDC features, mostly: login and logout. Undoubtedly you may use Keycloak in various 
other exotic ways but this limited scope ensures the extension stays maintainable. Please keep 
that in mind when submitting a pull-request.

### Common errors

```text
redirect error 'invalid_request' Invalid scopes: openid profile email
```

Keycloak version too old. Run this extension in [legacy mode](#compatibility).

## Terminology

- `OIDC`: OpenID Connect - A layer built on top of the OAuth 2.0 protocol
- `IdP`: The identity provider, also sometimes called `OP` (OpenID Provider). In our case; Keycloak.
- `Client`: the application that interacts with a `IdP` (Keycloak), in our case Quart. Sometimes also called `Relying Party`.
- Client Types: 
- `confidential` - Clients **capable** of maintaining the confidentiality of their credentials, so backend applications made in PHP, Perl, Python, etc. The example in "[Quick Start](#QuickStart) is an example of a confidential client.
- `public` - Clients **incapable** of maintaining the confidentiality of their credentials: VueJS, React, Angular.
- `User Agent`: the end-user, often times 'the browser'.
