#!/usr/bin/env python3
"""Drives clients through gatekeeper (see e2e.sh): a web app (cookie session, cross origin from a UI),
a mobile app (public client, PKCE, Bearer) and a service (client credentials, Bearer)."""
import base64, hashlib, http.cookiejar, json, os, re, secrets, sys
import urllib.error, urllib.parse, urllib.request

GK, ISS = os.environ["GK"], os.environ["ISSUER"]
EMAIL, PASSWORD = os.environ["EMAIL"], os.environ["PASSWORD"]
UI = os.environ["UI_ORIGIN"]  # a registered web app, other origin than the gateway
MOBILE_CLIENT, MOBILE_REDIRECT = os.environ["MOBILE_CLIENT"], os.environ["MOBILE_REDIRECT"]
SVC_CLIENT, SVC_SECRET = os.environ["SERVICE_CLIENT"], os.environ["SERVICE_SECRET"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Agent:
    """An HTTP client with its own cookie jar (a browser, or a phone)."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def call(self, method, url, data=None, headers=None, js=None):
        h = dict(headers or {})
        body = None
        if js is not None:
            body, h["Content-Type"] = json.dumps(js).encode(), "application/json"
        elif data is not None:
            body = urllib.parse.urlencode(data).encode()
        try:
            r = self.opener.open(urllib.request.Request(url, method=method, headers=h, data=body))
        except urllib.error.HTTPError as e:
            r = e
        return r.status, dict(r.headers), r.read().decode()

    def cookie(self, name):
        return next((c.value for c in self.jar if c.name == name), None)


def check(name, cond, extra=""):
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else " " + str(extra)))
    if not cond:
        sys.exit(1)


def absolute(base, loc):
    return loc if "://" in loc else base + loc


def identity_login(agent, authorize_url):
    """Follows an authorize URL through the identity login form; returns the final redirect."""
    s, h, b = agent.call("GET", authorize_url)
    s, h, b = agent.call("GET", absolute(ISS, h["Location"]))
    csrf = re.search(r'name="csrf" value="([^"]+)"', b).group(1)
    ret = re.search(r'name="return_to" value="([^"]*)"', b).group(1).replace("&amp;", "&").replace("&#43;", "+")
    s, h, b = agent.call("POST", f"{ISS}/login", {"csrf": csrf, "return_to": ret, "email": EMAIL, "password": PASSWORD})
    check("identity login", s in (302, 303), (s, b[:200]))
    s, h, b = agent.call("GET", absolute(ISS, h["Location"]))
    return s, h


web = Agent()
call, cookie = web.call, web.cookie

s, h, b = call("GET", f"{GK}/auth/me")
check("anonymous /auth/me is 401", s == 401, (s, b))
s, h, b = call("GET", f"{GK}/api/roles")
check("anonymous route is 401", s == 401, (s, b))

# CORS: the UI origin is answered with credentials, any other origin is not; the preflight needs no session
s, h, b = call("OPTIONS", f"{GK}/api/roles", headers={
    "Origin": UI, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type,csrf-token"})
check("preflight from the UI is accepted", s == 204 and h.get("Access-Control-Allow-Origin") == UI
      and h.get("Access-Control-Allow-Credentials") == "true", (s, h))
s, h, b = call("OPTIONS", f"{GK}/api/roles", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
check("preflight from a foreign origin is not", "Access-Control-Allow-Origin" not in h and s != 204, (s, h))
s, h, b = call("GET", f"{GK}/auth/me", headers={"Origin": UI})
check("CORS headers on a real response", s == 401 and h.get("Access-Control-Allow-Origin") == UI, (s, h))

# login started by the UI: gatekeeper -> identity -> login form -> back to gatekeeper -> back to the UI
s, h, b = call("GET", f"{GK}/auth/login?return_to=" + urllib.parse.quote(UI + "/app", safe=""))
check("login redirects to identity", s == 302 and h["Location"].startswith(ISS + "/oauth2/authorize"), (s, h))
check("state cookie set", cookie("login-state"))
s, h = identity_login(web, h["Location"])
check("identity redirects to the callback", s == 302 and h["Location"].startswith(GK + "/auth/callback"), (s, h))
cb = h["Location"]

# a callback with a foreign state is refused (login CSRF)
bad = re.sub(r"state=[^&]+", "state=forged", cb)
s, _, b = call("GET", bad)
check("callback with another state refused", s == 400, (s, b))

s, h, b = call("GET", cb)
check("callback creates the session and returns to the UI", s == 302 and h["Location"] == UI + "/app", (s, h, b))
sid = cookie("session")
check("session cookie is opaque, not a JWT", sid and sid.count(".") != 2, sid)

s, h, b = call("GET", f"{GK}/auth/me", headers={"Origin": UI})
me = json.loads(b)
check("/auth/me", s == 200 and me["csrf_token"] and "*" in me["perms"], (s, b))
tok = me["csrf_token"]
check("no token in /auth/me", "access_token" not in b and "eyJ" not in b, b)

# a route: JSON in, gRPC to identity with an exchanged token, JSON out
s, h, b = call("GET", f"{GK}/api/roles", headers={"Origin": UI})
roles = json.loads(b)
check("GET /api/roles reaches identity", s == 200 and any(r["name"] == "admin" for r in roles.get("roles", [])), (s, b))
check("... with CORS headers", h.get("Access-Control-Allow-Origin") == UI, h)

# unsafe methods: Origin + Csrf-Token
body = {"role": {"name": "e2e-" + os.urandom(3).hex(), "description": "from e2e", "permissions": ["identity:*:read"]}}
s, h, b = call("POST", f"{GK}/api/roles", js=body)
check("POST without Origin/CSRF refused", s == 403, (s, b))
s, h, b = call("POST", f"{GK}/api/roles", js=body, headers={"Origin": "https://evil.example", "Csrf-Token": tok})
check("POST from a foreign Origin refused", s == 403, (s, b))
s, h, b = call("POST", f"{GK}/api/roles", js=body, headers={"Origin": UI, "Csrf-Token": "wrong"})
check("POST with a wrong CSRF token refused", s == 403, (s, b))
s, h, b = call("POST", f"{GK}/api/roles", js=body, headers={"Origin": UI, "Csrf-Token": tok})
check("POST with Origin and CSRF goes through", s == 200, (s, b))
s, h, b = call("POST", f"{GK}/api/roles", js={"nope": 1}, headers={"Origin": UI, "Csrf-Token": tok})
check("unknown JSON field is 400", s == 400, (s, b))

# logout: back to the UI that asked
s, h, b = call("POST", f"{GK}/auth/logout?return_to=" + urllib.parse.quote(UI + "/", safe=""), headers={"Origin": UI, "Csrf-Token": tok})
out = json.loads(b).get("logout_url", "") if s == 200 else ""
check("logout returns the identity logout URL with the UI as target",
      out.startswith(ISS + "/oauth2/logout") and urllib.parse.quote(UI + "/", safe="") in out, (s, b))
s, h, b = call("GET", f"{GK}/auth/me")
check("session is gone after logout", s == 401, (s, b))

# ---- mobile app: public client, PKCE through the system browser, then Bearer ----
phone = Agent()
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
state = secrets.token_urlsafe(16)
q = urllib.parse.urlencode({
    "response_type": "code", "client_id": MOBILE_CLIENT, "redirect_uri": MOBILE_REDIRECT, "scope": "openid profile email offline_access",
    "state": state, "nonce": secrets.token_urlsafe(16), "code_challenge": challenge, "code_challenge_method": "S256"})
s, h = identity_login(phone, f"{ISS}/oauth2/authorize?{q}")
check("authorize redirects to the app scheme", s == 302 and h["Location"].startswith(MOBILE_REDIRECT), (s, h))
code = urllib.parse.parse_qs(urllib.parse.urlparse(h["Location"]).query)["code"][0]
s, h, b = phone.call("POST", f"{ISS}/oauth2/token", {
    "grant_type": "authorization_code", "code": code, "redirect_uri": MOBILE_REDIRECT, "client_id": MOBILE_CLIENT, "code_verifier": verifier})
check("mobile token request", s == 200, (s, b))
access = json.loads(b)["access_token"]
bearer = {"Authorization": "Bearer " + access}

s, h, b = Agent().call("GET", f"{GK}/api/roles")
check("no Bearer, no cookie: 401", s == 401, (s, b))
s, h, b = Agent().call("GET", f"{GK}/api/roles", headers={"Authorization": "Bearer " + access[:-4] + "AAAA"})
check("tampered Bearer is 401", s == 401 and "www-authenticate" in {k.lower() for k in h}, (s, h, b))
s, h, b = Agent().call("GET", f"{GK}/api/roles", headers=bearer)
check("mobile: GET with Bearer reaches identity", s == 200 and any(r["name"] == "admin" for r in json.loads(b).get("roles", [])), (s, b))
body = {"role": {"name": "e2e-" + os.urandom(3).hex(), "description": "from mobile", "permissions": ["identity:*:read"]}}
s, h, b = Agent().call("POST", f"{GK}/api/roles", js=body, headers=bearer)
check("mobile: POST with Bearer needs no Origin/CSRF", s == 200, (s, b))
s, h, b = web.call("GET", f"{GK}/api/roles", headers={"Authorization": "Bearer garbage"})
check("a bad Bearer is never rescued by a cookie", s == 401, (s, b))

# ---- service: client credentials for the gateway audience, then Bearer ----
basic = "Basic " + base64.b64encode(f"{SVC_CLIENT}:{SVC_SECRET}".encode()).decode()
s, h, b = Agent().call("POST", f"{ISS}/oauth2/token", {"grant_type": "client_credentials", "audience": "gatekeeper"}, headers={"Authorization": basic})
check("service token request", s == 200, (s, b))
svc = {"Authorization": "Bearer " + json.loads(b)["access_token"]}
s, h, b = Agent().call("GET", f"{GK}/api/roles", headers=svc)
check("service: GET with Bearer reaches identity", s == 200 and any(r["name"] == "admin" for r in json.loads(b).get("roles", [])), (s, b))
print("ALL OK")
