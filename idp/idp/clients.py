"""Relying parties come from JSON files (IDP_CLIENTS_FILE, space-separated), synced into the database at every start.

Each entry:
  {"client_id": "demo-gate", "name": "Demo site", "url": "${GATE_PUBLIC_URL}/",
   "redirect_uris": ["${GATE_PUBLIC_URL}/redirect_uri"],
   "post_logout_redirect_uris": ["${GATE_PUBLIC_URL}/"],
   "auth_method": "client_secret_basic",          # or "none" for a public (browser/mobile) client
   "secret_file": "/shared/demo-gate.secret"}     # made on first start; the relying party reads it from there

A browser app (Angular, no back-end secret) is a public client: "auth_method": "none", no secret_file, and PKCE
(always required here) protects the code. Its redirect URI is the app's PUBLIC_URL + UI_BASE_PATH.

${VARS} are filled from the environment, so the same file works on a laptop and on a server.
"""

import json
import os
import secrets
import time

from .models import Client, db


def _expand(v):
    if isinstance(v, str):
        out = os.path.expandvars(v)
        if "$" in out:
            raise ValueError(f"unset variable in clients file: {v}")
        return out
    if isinstance(v, list):
        return [_expand(x) for x in v]
    return v


def _secret(path):
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    value = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value + "\n")
    return value


def sync_clients(path, log):
    entries = []
    for p in (path or "").replace(",", " ").split():  # several files: e.g. the committed example + a private local list
        if not os.path.exists(p):
            log.warning("no clients file at %r", p)
            continue
        with open(p) as f:
            entries += [{k: _expand(v) for k, v in e.items()} for e in json.load(f)]
    if not entries:
        log.warning("no clients configured: no site can sign in yet")
    ids = [e["client_id"] for e in entries]
    if len(ids) != len(set(ids)):
        raise ValueError(f"a client_id is listed twice: {sorted(i for i in set(ids) if ids.count(i) > 1)}")
    for e in entries:
        method = e.get("auth_method", "client_secret_basic")
        c = Client.query.filter_by(client_id=e["client_id"]).first() or Client(
            client_id=e["client_id"], client_id_issued_at=int(time.time())
        )
        c.client_secret = "" if method == "none" else _secret(e["secret_file"])
        c.set_client_metadata(
            {
                "client_name": e.get("name", e["client_id"]),
                "client_uri": e.get("url", ""),
                "redirect_uris": e["redirect_uris"],
                "post_logout_redirect_uris": e.get("post_logout_redirect_uris", []),
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "scope": " ".join(e.get("scopes", ["openid", "profile", "email"])),
                "token_endpoint_auth_method": method,
            }
        )
        db.session.add(c)
    keep = {e["client_id"] for e in entries}
    for c in Client.query.all():
        if c.client_id not in keep:  # the file is the source of truth: a client taken out of it can't sign in any more
            db.session.delete(c)
    db.session.commit()
    log.info("clients: %s", ", ".join(e["client_id"] for e in entries))
