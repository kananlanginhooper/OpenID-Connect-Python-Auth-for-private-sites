"""A small self-hosted OpenID Connect provider for private sites.

Settings (environment):
  IDP_ISSUER        public URL of this provider, exactly as browsers reach it (e.g. http://localhost:9000)
  IDP_INTERNAL_URL  optional: how containers on the same network reach it (e.g. http://idp:9000), see discovery()
  IDP_DATA_DIR      where the database, signing key and session secret live (default /data)
  DATABASE_URL      any SQLAlchemy URL (default sqlite:///<IDP_DATA_DIR>/idp.sqlite3)
  IDP_CLIENTS_FILE  JSON list of relying parties (see clients.py)
"""
import logging
import os
import secrets

from flask import Flask

from .clients import sync_clients
from .models import db
from .oauth import init_oauth, load_signing_key

log = logging.getLogger("idp")


def _session_secret(data_dir):
    path = os.path.join(data_dir, "session-secret")
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


def create_app():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    issuer = os.environ.get("IDP_ISSUER", "http://localhost:9000").rstrip("/")
    data_dir = os.environ.get("IDP_DATA_DIR", "/data")
    os.makedirs(data_dir, exist_ok=True)
    if issuer.startswith("http://"):
        # Authlib refuses plain http (except localhost); a demo or a private LAN without TLS is the reason to allow it.
        os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "1"
        log.warning("issuer is plain http: fine for a demo or a closed LAN, use https anywhere else")

    app = Flask(__name__)
    app.config.update(
        ISSUER=issuer,
        INTERNAL_URL=os.environ.get("IDP_INTERNAL_URL", "").rstrip("/"),
        SECRET_KEY=_session_secret(data_dir),
        SIGNING_KEY=load_signing_key(data_dir),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL") or f"sqlite:///{os.path.join(data_dir, 'idp.sqlite3')}",
        SESSION_COOKIE_NAME="idp_session",      # sites on the same host (other ports) share cookies, so the name must be ours
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=issuer.startswith("https://"),
        PERMANENT_SESSION_LIFETIME=int(os.environ.get("IDP_SESSION_HOURS", "12")) * 3600,
        OAUTH2_TOKEN_EXPIRES_IN={"authorization_code": 3600},
    )
    db.init_app(app)
    init_oauth(app)

    from .routes import bp
    app.register_blueprint(bp)
    from .cli import register
    register(app)

    with app.app_context():
        db.create_all()
        sync_clients(os.environ.get("IDP_CLIENTS_FILE"), log)
        from .models import User
        if User.query.count() == 0:
            log.warning("no users yet: add one with  docker compose exec idp flask user add you@example.com")
        db.engine.dispose()   # gunicorn --preload forks after this: workers open their own connections
    log.info("issuer %s", issuer)
    return app
