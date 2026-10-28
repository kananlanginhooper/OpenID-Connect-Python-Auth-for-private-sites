"""The OpenID Connect provider: authorization-code flow with PKCE (S256, required), RS256 ID tokens, bearer userinfo."""
import json
import os
import time

from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator, create_query_client_func, create_save_token_func
from authlib.jose import JsonWebKey
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oidc.core import UserInfo
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from flask import current_app, session

from .models import AuthorizationCode, Client, Token, User, db

SCOPES = ["openid", "profile", "email"]
ID_TOKEN_TTL = 3600

server = AuthorizationServer()
require_oauth = ResourceProtector()


def load_signing_key(data_dir):
    """The RSA key ID tokens are signed with: made once, kept in the data volume, published at /jwks."""
    path = os.path.join(data_dir, "signing-key.json")
    if not os.path.exists(path):
        key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        jwk = key.as_dict(is_private=True)
        jwk.update(kid=key.thumbprint(), use="sig", alg="RS256")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(jwk, f)
    with open(path) as f:
        return json.load(f)


def public_jwks():
    private = current_app.config["SIGNING_KEY"]
    public = JsonWebKey.import_key(private).as_dict(is_private=False)
    public.update(kid=private["kid"], use="sig", alg="RS256")
    return {"keys": [public]}


def user_info(user, scope):
    info = UserInfo(sub=user.sub)
    if "profile" in scope:
        info["name"] = user.name or user.email
        info["preferred_username"] = user.email
    if "email" in scope:
        info["email"] = user.email
        info["email_verified"] = True   # accounts are made by the admin, not self-registered
    return info


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        p = request.payload
        item = AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=p.redirect_uri,
            scope=p.scope,
            user_id=request.user.id,
            nonce=p.data.get("nonce"),
            auth_time=session.get("auth_time") or int(time.time()),
            code_challenge=p.data.get("code_challenge"),
            code_challenge_method=p.data.get("code_challenge_method"),
        )
        db.session.add(item)
        db.session.commit()
        return item

    def query_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(code=code, client_id=client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        user = db.session.get(User, authorization_code.user_id)
        return user if user and user.active else None


class OpenIDCode(_OpenIDCode):
    def exists_nonce(self, nonce, request):
        return AuthorizationCode.query.filter_by(client_id=request.payload.client_id, nonce=nonce).first() is not None

    def get_jwt_config(self, grant, client):
        return {"key": current_app.config["SIGNING_KEY"], "alg": "RS256", "iss": current_app.config["ISSUER"], "exp": ID_TOKEN_TTL}

    def generate_user_info(self, user, scope):
        return user_info(user, scope)


def init_oauth(app):
    server.init_app(app, query_client=create_query_client_func(db.session, Client), save_token=create_save_token_func(db.session, Token))
    server.register_grant(AuthorizationCodeGrant, [OpenIDCode(require_nonce=False), CodeChallenge(required=True)])
    require_oauth.register_token_validator(create_bearer_token_validator(db.session, Token)())
