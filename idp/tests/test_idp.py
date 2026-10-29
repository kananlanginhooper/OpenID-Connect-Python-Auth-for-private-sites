"""The provider end to end, in-process (Flask test client, SQLite in a temp dir)."""

import base64
import hashlib
import json
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest

ISSUER = "http://localhost:9000"
SPA = "http://localhost:5999"
PASSWORD = "correct horse battery staple"


@pytest.fixture
def app(tmp_path, monkeypatch):
    clients = tmp_path / "clients.json"
    clients.write_text(
        json.dumps(
            [
                {
                    "client_id": "spa",
                    "name": "Test app",
                    "url": SPA + "/",
                    "redirect_uris": [SPA + "/"],
                    "post_logout_redirect_uris": [SPA + "/"],
                    "auth_method": "none",
                },
            ]
        )
    )
    for k, v in {
        "IDP_ISSUER": ISSUER,
        "IDP_DATA_DIR": str(tmp_path / "data"),
        "IDP_CLIENTS_FILE": str(clients),
        "FRAME_ANCESTORS": "http://wrapper.test",
        "DB_HOST": "",
        "DATABASE_URL": "",
    }.items():
        monkeypatch.setenv(k, v)
    from idp import create_app
    from idp.models import User, db

    app = create_app()
    with app.app_context():
        u = User(email="user@example.test", name="Test User")
        u.set_password(PASSWORD)
        db.session.add(u)
        db.session.commit()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorize_url(challenge, nonce=None, **extra):
    q = {
        "response_type": "code",
        "client_id": "spa",
        "redirect_uri": SPA + "/",
        "scope": "openid email profile",
        "state": "st",
        "nonce": nonce or secrets.token_hex(8),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        **extra,
    }
    return "/authorize?" + urlencode(q)


def sign_in(client, next_url):
    page = client.get(next_url, follow_redirects=True).get_data(as_text=True)
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    nxt = re.search(r'name="next" value="([^"]+)"', page).group(1).replace("&amp;", "&")
    return client.post("/login", data={"csrf": csrf, "next": nxt, "email": "user@example.test", "password": PASSWORD})


def test_discovery_and_jwks(client):
    d = client.get("/.well-known/openid-configuration").get_json()
    assert d["issuer"] == ISSUER and d["code_challenge_methods_supported"] == ["S256"]
    assert d["token_endpoint"] == ISSUER + "/token"
    keys = client.get("/jwks").get_json()["keys"]
    assert len(keys) == 1 and keys[0]["kty"] == "RSA" and "d" not in keys[0]  # public part only


def test_headers_frame_and_cors(client):
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert csp == f"frame-ancestors 'self' http://wrapper.test {SPA}"
    ok = client.options("/token", headers={"Origin": SPA, "Access-Control-Request-Method": "POST"})
    assert ok.status_code == 204 and ok.headers["Access-Control-Allow-Origin"] == SPA
    bad = client.options("/token", headers={"Origin": "http://evil.test", "Access-Control-Request-Method": "POST"})
    assert "Access-Control-Allow-Origin" not in bad.headers


def test_pkce_is_required(client):
    q = {"response_type": "code", "client_id": "spa", "redirect_uri": SPA + "/", "scope": "openid"}
    assert client.get("/authorize?" + urlencode(q)).status_code == 400
    assert (
        client.get(
            "/authorize?" + urlencode({**q, "code_challenge": "x" * 43, "code_challenge_method": "plain"})
        ).status_code
        == 400
    )


def test_wrong_password(client):
    page = client.get("/login").get_data(as_text=True)
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    r = client.post("/login", data={"csrf": csrf, "email": "user@example.test", "password": "nope"})
    assert r.status_code == 401 and "Wrong email or password" in r.get_data(as_text=True)


def test_code_flow_public_client(client):
    verifier, challenge = pkce()
    nonce = secrets.token_hex(8)
    first = client.get(authorize_url(challenge, nonce))
    assert first.status_code == 302 and "/login" in first.headers["Location"]
    assert sign_in(client, first.headers["Location"]).status_code == 302

    back = client.get(authorize_url(challenge, nonce))  # signed in now: straight back to the app
    loc = urlsplit(back.headers["Location"])
    params = dict(parse_qsl(loc.query))
    assert f"{loc.scheme}://{loc.netloc}" == SPA and params["state"] == "st"

    form = {"grant_type": "authorization_code", "code": params["code"], "redirect_uri": SPA + "/", "client_id": "spa"}
    assert client.post("/token", data=form).status_code == 400  # no code_verifier
    tok = client.post("/token", data={**form, "code_verifier": verifier}, headers={"Origin": SPA})
    assert tok.status_code == 200 and tok.headers["Access-Control-Allow-Origin"] == SPA
    body = tok.get_json()
    assert {"access_token", "id_token"} <= set(body)

    info = client.get("/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"}).get_json()
    assert info["email"] == "user@example.test"

    from authlib.jose import JsonWebKey, jwt

    claims = jwt.decode(body["id_token"], JsonWebKey.import_key_set(client.get("/jwks").get_json()))
    claims.validate()
    assert claims["iss"] == ISSUER and claims["nonce"] == nonce and claims["email"] == "user@example.test"

    assert client.get(authorize_url(challenge, nonce)).status_code == 400  # a nonce can't be replayed


def test_logout_only_to_registered_addresses(client):
    r = client.get("/logout?" + urlencode({"post_logout_redirect_uri": SPA + "/", "state": "x"}))
    assert r.status_code == 302 and r.headers["Location"] == SPA + "/?state=x"
    r = client.get("/logout?" + urlencode({"post_logout_redirect_uri": "http://evil.test/"}))
    assert r.status_code == 200  # signed-out page, no redirect
