"""A small self-hosted OpenID Connect provider for private sites.

Settings (environment):
  IDP_ISSUER        public URL of this provider, exactly as browsers reach it (e.g. http://localhost:9000)
  IDP_INTERNAL_URL  optional: how containers on the same network reach it (e.g. http://idp:9000), see discovery()
  IDP_DATA_DIR      where the database, signing key and session secret live (default /data)
  DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD   Postgres (when DB_HOST is set)
  DATABASE_URL      any SQLAlchemy URL instead (default: sqlite:///<IDP_DATA_DIR>/idp.sqlite3)
  IDP_CLIENTS_FILE  JSON list of relying parties (see clients.py)
  FRAME_ANCESTORS   wrapper origins allowed to frame the login page (registered sites are always allowed)
  FORWARDED_ALLOW_IPS  reverse proxies whose X-Forwarded-* headers are trusted (comma-separated, or *)
"""
import logging
import os
import secrets
from urllib.parse import urlsplit

from flask import Flask, request

from .clients import sync_clients
from .models import db
from .oauth import init_oauth, load_signing_key

log = logging.getLogger("idp")
CORS_PATHS = {"/.well-known/openid-configuration", "/jwks", "/token", "/userinfo"}


def _session_secret(data_dir):
    path = os.path.join(data_dir, "session-secret")
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


def _database_url(data_dir):
    """DATABASE_URL, else Postgres from DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD, else SQLite in the data volume."""
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    if os.environ.get("DB_HOST"):
        from sqlalchemy import URL
        return URL.create("postgresql+psycopg", username=os.environ.get("DB_USER", "idp"),
                          password=os.environ.get("DB_PASSWORD", ""), host=os.environ["DB_HOST"],
                          port=int(os.environ.get("DB_PORT", "5432")), database=os.environ.get("DB_NAME", "idp"))
    return f"sqlite:///{os.path.join(data_dir, 'idp.sqlite3')}"


def _upgrade():
    """Columns added after a table was first created (create_all only makes missing tables)."""
    from sqlalchemy import inspect, text
    if "issued_at" not in {c["name"] for c in inspect(db.engine).get_columns("authorization_code")}:
        with db.engine.begin() as c:
            c.execute(text("ALTER TABLE authorization_code ADD COLUMN issued_at INTEGER NOT NULL DEFAULT 0"))
        log.info("database upgraded: authorization_code.issued_at")


def _behind_proxy(app, trusted):
    """Honor X-Forwarded-For/Proto/Host (TLS ending at a reverse proxy) only from the proxies in FORWARDED_ALLOW_IPS."""
    from werkzeug.middleware.proxy_fix import ProxyFix
    ips = {i.strip() for i in trusted.split(",") if i.strip()}
    if not ips:
        return
    plain, fixed = app.wsgi_app, ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.wsgi_app = lambda env, start: (fixed if "*" in ips or env.get("REMOTE_ADDR") in ips else plain)(env, start)


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
        SQLALCHEMY_DATABASE_URI=_database_url(data_dir),
        SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
        SESSION_COOKIE_NAME="idp_session",      # sites on the same host (other ports) share cookies, so the name must be ours
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=issuer.startswith("https://"),
        PERMANENT_SESSION_LIFETIME=int(os.environ.get("IDP_SESSION_HOURS", "12")) * 3600,
        OAUTH2_TOKEN_EXPIRES_IN={"authorization_code": 3600},
    )
    _behind_proxy(app, os.environ.get("FORWARDED_ALLOW_IPS", ""))
    # Apps sign in inside their own iframe in the dashboard wrapper, so the login page may be framed by the wrapper
    # (FRAME_ANCESTORS) and by every registered site (the origins of its redirect URIs, added after the client sync).
    ancestors = ["'self'", *os.environ.get("FRAME_ANCESTORS", "").replace(",", " ").split()]
    # Browser apps (public clients) call discovery, jwks, token and userinfo with fetch(), so those answer CORS for
    # registered sites only. The login page itself is a normal navigation and needs none.
    client_origins = set()

    @app.after_request
    def headers(r):
        r.headers.setdefault("Content-Security-Policy", "frame-ancestors " + " ".join(ancestors))
        origin = request.headers.get("Origin")
        if origin in client_origins and request.path in CORS_PATHS:
            r.headers["Access-Control-Allow-Origin"] = origin
            r.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
            r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            r.headers["Access-Control-Max-Age"] = "600"
            r.headers.add("Vary", "Origin")
        return r

    db.init_app(app)
    init_oauth(app)

    from .routes import bp
    app.register_blueprint(bp)
    from .cli import register
    register(app)

    with app.app_context():
        db.create_all()
        _upgrade()
        sync_clients(os.environ.get("IDP_CLIENTS_FILE"), log)
        from .models import Client, User
        for c in Client.query.all():
            for uri in c.redirect_uris:
                u = urlsplit(uri)
                client_origins.add(f"{u.scheme}://{u.netloc}")
                if f"{u.scheme}://{u.netloc}" not in ancestors:
                    ancestors.append(f"{u.scheme}://{u.netloc}")
        if User.query.count() == 0:
            log.warning("no users yet: add one with  docker compose exec idp flask user add you@example.com")
        db.engine.dispose()   # gunicorn --preload forks after this: workers open their own connections
    log.info("issuer %s", issuer)
    return app
