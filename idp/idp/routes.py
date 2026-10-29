"""Endpoints: discovery, JWKS, authorize (+ login page), token, userinfo, logout, and a small account page."""
import hmac
import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for

from .models import Client, User, db
from .oauth import SCOPES, public_jwks, require_oauth, server, user_info

bp = Blueprint("idp", __name__)


def current_user():
    uid = session.get("uid")
    user = db.session.get(User, uid) if uid else None
    return user if user and user.active else None


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def without_prompt_login(path):
    """The /authorize URL to come back to after signing in, minus prompt=login (or it would ask again forever)."""
    u = urlsplit(path)
    q = [(k, " ".join(p for p in v.split() if p != "login")) if k == "prompt" else (k, v) for k, v in parse_qsl(u.query, keep_blank_values=True)]
    return urlunsplit(("", "", u.path, urlencode([(k, v) for k, v in q if not (k == "prompt" and not v)]), ""))


def safe_next(target):
    return target if target and target.startswith("/") and not target.startswith("//") else url_for(".home")


@bp.route("/.well-known/openid-configuration", methods=["GET", "OPTIONS"])
def discovery():
    iss = current_app.config["ISSUER"]
    # ?internal=1: a relying party in the same docker network gets the server-to-server endpoints (token, userinfo,
    # jwks) on IDP_INTERNAL_URL, since the public address may not be reachable from inside a container.
    back = (current_app.config["INTERNAL_URL"] if request.args.get("internal") else None) or iss
    return jsonify({
        "issuer": iss,
        "authorization_endpoint": iss + "/authorize",
        "token_endpoint": back + "/token",
        "userinfo_endpoint": back + "/userinfo",
        "jwks_uri": back + "/jwks",
        "end_session_endpoint": iss + "/logout",
        "scopes_supported": SCOPES,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": ["sub", "name", "preferred_username", "email", "email_verified", "auth_time", "nonce"],
    })


@bp.route("/jwks", methods=["GET", "OPTIONS"])
def jwks():
    return jsonify(public_jwks())


@bp.route("/authorize", methods=["GET", "POST"])
def authorize():
    user = current_user()
    prompt = request.values.get("prompt", "").split()
    try:
        server.get_consent_grant(end_user=user)   # checks client, redirect_uri, scope and PKCE before anything else
    except OAuth2Error as e:
        if user is None and "none" in prompt:
            return server.create_authorization_response(grant_user=None)   # login_required, sent back to the site
        return render_template("error.html", error=e.error, description=e.description), 400
    if not request.values.get("code_challenge") or request.values.get("code_challenge_method") != "S256":
        # Authlib only insists on PKCE for public clients; here every client must use it (OAuth 2.1)
        return render_template("error.html", error="invalid_request", description="PKCE with S256 is required"), 400
    if user is None and "none" in prompt:
        return server.create_authorization_response(grant_user=None)   # the site asked not to show a login page
    if user is None or "login" in prompt:
        return redirect(url_for(".login", next=without_prompt_login(request.full_path)))
    # Sites are registered by the admin, so there is no consent screen: signing in is the consent.
    return server.create_authorization_response(grant_user=user)


@bp.route("/login", methods=["GET", "POST"])
def login():
    nxt = safe_next(request.values.get("next"))
    error = None
    if request.method == "POST":
        if not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "")):
            error = "The form expired. Try again."
        else:
            user = User.query.filter_by(email=request.form.get("email", "").strip().lower()).first()
            if user and user.active and user.check_password(request.form.get("password", "")):
                session.clear()
                session.permanent = True
                session.update(uid=user.id, auth_time=int(time.time()))
                return redirect(nxt)
            time.sleep(1)   # slows down password guessing
            error = "Wrong email or password."
    client = None
    if nxt.startswith("/authorize"):
        cid = dict(parse_qsl(urlsplit(nxt).query)).get("client_id")
        client = Client.query.filter_by(client_id=cid).first() if cid else None
    return render_template("login.html", next=nxt, error=error, csrf=csrf_token(),
                           site=client.client_name if client else None, email=request.form.get("email", "")), (401 if error else 200)


@bp.route("/token", methods=["POST", "OPTIONS"])
def token():
    if request.method == "OPTIONS":   # CORS preflight from a browser app; the headers are added in __init__
        return "", 204
    return server.create_token_response()


@bp.route("/userinfo", methods=["GET", "POST", "OPTIONS"])
def userinfo():
    if request.method == "OPTIONS":
        return "", 204
    return _userinfo()


@require_oauth("openid")
def _userinfo():
    return jsonify(user_info(current_token.user, current_token.scope))


@bp.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    target = request.values.get("post_logout_redirect_uri")
    allowed = {u for c in Client.query.all() for u in c.client_metadata.get("post_logout_redirect_uris", [])}
    if target and target in allowed:   # only addresses a registered site listed, never an open redirect
        state = request.values.get("state")
        return redirect(target + (("&" if "?" in target else "?") + urlencode({"state": state}) if state else ""))
    return render_template("message.html", title="Signed out", text="You are signed out.")


@bp.get("/")
def home():
    user = current_user()
    if not user:
        return redirect(url_for(".login"))
    sites = [{"name": c.client_name, "url": c.client_uri} for c in Client.query.all()]
    return render_template("home.html", user=user, sites=sites)


@bp.get("/healthz")
def healthz():
    return {"ok": True}
