"""End-to-end check of a public (browser) client: sign-in, authorize with PKCE, token without a secret, nonce replay,
silent re-authorize (SSO), CORS for the registered origin only, userinfo, ID-token signature.

Register a public client first (auth_method "none") whose redirect URI is REDIRECT, then, from the repo root:
  docker run --rm --network host -v "$PWD/tests:/t:ro" -e IDP=http://localhost:9000 -e CLIENT_ID=test-spa     -e REDIRECT=http://localhost:5999/ oidc-auth-idp python /t/public_client_e2e.py EMAIL PASSWORD_FILE
PASSWORD_FILE holds a line "password=...". Never commit it.
"""
import base64, hashlib, http.cookiejar, json, re, secrets, sys, urllib.parse, urllib.request

import os
IDP = os.environ.get("IDP", "http://localhost:9000")
CID = os.environ.get("CLIENT_ID", "test-spa")
REDIR = os.environ.get("REDIRECT", "http://localhost:5999/")
ORIGIN = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(REDIR))
email, pwfile = sys.argv[1], sys.argv[2]
password = [l.split("=", 1)[1].strip() for l in open(pwfile) if l.startswith("password=")][0]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)


def req(url, data=None, headers=None, method=None):
    r = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        resp = op.open(r)
    except urllib.error.HTTPError as e:
        resp = e
    return resp.status, dict(resp.headers), resp.read().decode()


verifier = secrets.token_urlsafe(48)
N1, N2 = secrets.token_hex(8), secrets.token_hex(8)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
q = urllib.parse.urlencode({"response_type": "code", "client_id": CID, "redirect_uri": REDIR, "scope": "openid email profile",
                            "state": "s1", "nonce": N1, "code_challenge": challenge, "code_challenge_method": "S256"})
st, h, body = req(f"{IDP}/authorize?{q}")
assert st == 302 and "/login" in h["Location"], (st, h.get("Location"))
st, h, body = req(IDP + h["Location"])
csrf = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
nxt = re.search(r'name="next" value="([^"]+)"', body).group(1).replace("&amp;", "&")
st, h, body = req(f"{IDP}/login", urllib.parse.urlencode({"csrf": csrf, "next": nxt, "email": email, "password": password}).encode())
assert st == 302, ("login", st)
st, h, body = req(IDP + h["Location"])
loc = urllib.parse.urlsplit(h["Location"])
params = dict(urllib.parse.parse_qsl(loc.query))
assert loc.geturl().startswith(REDIR) and params["state"] == "s1", h["Location"]
print("authorize -> code ok")

st, h, body = req(f"{IDP}/token", method="OPTIONS", headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST"})
print("preflight", st, h.get("Access-Control-Allow-Origin"))
assert h.get("Access-Control-Allow-Origin") == ORIGIN
st, h, body = req(f"{IDP}/token", method="OPTIONS", headers={"Origin": "http://evil.test", "Access-Control-Request-Method": "POST"})
assert "Access-Control-Allow-Origin" not in h, "CORS allowed an unregistered origin"
print("unregistered origin gets no CORS: ok")

form = {"grant_type": "authorization_code", "code": params["code"], "redirect_uri": REDIR, "client_id": CID}
st, h, body = req(f"{IDP}/token", urllib.parse.urlencode(form).encode(), {"Origin": ORIGIN})
assert st == 400, ("token without verifier must fail", st, body)
print("token without code_verifier refused:", json.loads(body)["error"])

st, h, body = req(f"{IDP}/authorize?{q}")
assert st == 400 and "Location" not in h, ("a reused nonce must be refused", st)
print("reused nonce refused: ok")
# a fresh request: the IdP session makes it silent (single sign-on)
q = q.replace(f"nonce={N1}", f"nonce={N2}")
st, h, body = req(f"{IDP}/authorize?{q}")
code = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(h["Location"]).query))["code"]
print("silent re-authorize (SSO):", "ok" if st == 302 else st)
st, h, body = req(f"{IDP}/token", urllib.parse.urlencode({**form, "code": code, "code_verifier": verifier}).encode(), {"Origin": ORIGIN})
assert st == 200, (st, body)
tok = json.loads(body)
print("token ok; CORS:", h.get("Access-Control-Allow-Origin"), "; keys:", sorted(tok))

st, h, body = req(f"{IDP}/userinfo", headers={"Authorization": f"Bearer {tok['access_token']}", "Origin": ORIGIN})
print("userinfo", st, json.loads(body).get("email"))

from authlib.jose import JsonWebKey, jwt  # noqa: E402
keys = JsonWebKey.import_key_set(json.loads(req(f"{IDP}/jwks")[2]))
claims = jwt.decode(tok["id_token"], keys)
claims.validate()
aud = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
assert claims["iss"] == IDP and aud == [CID] and claims["nonce"] == N2
print("id_token signature + iss/aud/nonce ok:", claims["email"])
