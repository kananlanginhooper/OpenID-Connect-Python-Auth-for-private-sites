# OpenID-Connect-Python-Auth-for-private-sites

A small, self-hosted OpenID Connect provider in Python, plus a ready-made gate that puts any private website behind it.
Everything runs as Docker containers with one `docker compose up -d`, and comes back by itself after a reboot.

```
browser ──► gate (Apache + mod_auth_openidc) ──► your private site
   │              │  token / userinfo / jwks over the compose network
   └────────► idp (Flask + Authlib): sign-in page, ID tokens
```

- **idp**: the provider. It supports the authorization-code flow with PKCE (S256, required for every client), RS256 ID tokens, `/userinfo`, discovery, JWKS and logout. Passwords are hashed with argon2. Accounts are made by an admin; nobody can sign themselves up.
- **gate**: Apache with [mod_auth_openidc](https://github.com/OpenIDC/mod_auth_openidc). Every request needs a signed-in user. The site behind it gets the user as `OIDC_CLAIM_*` headers and `REMOTE_USER` (the email). It never gets the sign-in cookies or the access token.
- **demo**: a stand-in private site ([traefik/whoami](https://github.com/traefik/whoami)) that echoes the request, so you can see what the site receives. It has no published port: you can reach it only through the gate.

## Run it

```bash
docker compose up -d
docker compose exec idp flask user add you@example.com --name "Your Name"
```

Open http://localhost:9080/. You're sent to the sign-in page at http://localhost:9000, and after you sign in you land on the demo site. To sign out of both: http://localhost:9080/redirect_uri?logout=http%3A%2F%2Flocalhost%3A9080%2F

All three services use `restart: unless-stopped`. Once Docker starts at boot, the stack is back without anyone starting it.

## Settings

Copy `.env.example` to `.env`. Both public URLs must be exactly what browsers type: scheme, host and port.

| Variable | Default | Meaning |
|---|---|---|
| `IDP_PUBLIC_URL` | `http://localhost:9000` | The provider's address, which is also the token issuer (`iss`) |
| `GATE_PUBLIC_URL` | `http://localhost:9080` | The protected site's address |
| `IDP_PORT` / `GATE_PORT` | `9000` / `9080` | Host ports |
| `IDP_BIND` / `GATE_BIND` | `0.0.0.0` | Set `127.0.0.1` to keep a port off the network, e.g. behind your own TLS proxy |
| `IDP_SESSION_HOURS` | `12` | How long a sign-in at the provider lasts |
| `FRAME_ANCESTORS` | (none) | Extra origins allowed to show the sign-in page in an iframe, e.g. a dashboard that frames your apps. Every registered site's origin (from its redirect URIs) is always allowed, since its login runs inside its own frame |
| `FORWARDED_ALLOW_IPS` | (none) | Reverse proxies whose `X-Forwarded-*` headers are trusted (comma-separated IPs, or `*`) |

Plain `http` is accepted so the demo runs anywhere; the provider logs a warning. Anywhere other than a closed LAN, put both behind TLS (`https://` URLs).

## Users

```bash
docker compose exec idp flask user add EMAIL [--name NAME]   # prompts for a password (12+ characters)
docker compose exec idp flask user list
docker compose exec idp flask user passwd EMAIL
docker compose exec idp flask user disable EMAIL             # or enable / remove
```

Add `--password-stdin` (and `-T` after `exec`) to pipe a password in from a script.

## Sites (relying parties)

[`config/clients.json`](config/clients.json) lists the sites allowed to sign in. It's synced into the database at every start, and a site taken out of the file can no longer sign in. `${VARS}` are filled from the environment. For a confidential client, the provider makes a secret on first start and writes it to the `shared` volume (`secret_file`). The relying party reads it from there, so no secret is ever written into a config file.

**Browser apps** (an Angular or other single-page app with no server-side secret) are **public clients**: `"auth_method": "none"` and no `secret_file`. PKCE, which is required for every client here, protects the code instead. The redirect URI is the app's own address (its public URL plus base path).
- The provider answers CORS on discovery, `/jwks`, `/token` and `/userinfo` for registered origins only.
- The sign-in page may be framed by registered origins, so an app shown in a dashboard iframe can sign in inside its frame.
- See [`config/clients.example.json`](config/clients.example.json). Your real list goes in `config/clients.local.json`, which is gitignored because addresses differ per network. `IDP_CLIENTS_FILE` loads both files.
- [`tests/public_client_e2e.py`](tests/public_client_e2e.py) checks the whole public-client flow.

To protect another site, add an entry to `clients.json`. Then add a second `gate` service with its own `OIDC_CLIENT_ID`, `UPSTREAM`, `GATE_PUBLIC_URL` and port. Any other OpenID Connect client works too; point it at `IDP_PUBLIC_URL/.well-known/openid-configuration`.

A client in the same compose network can use `IDP_INTERNAL_URL/.well-known/openid-configuration?internal=1`. That discovery document keeps the public issuer and sign-in page, but points the server-to-server endpoints (token, userinfo, jwks) at the internal address. A public URL like `localhost` isn't reachable from inside a container.

## Data

| Volume | Holds |
|---|---|
| `idp-data` | `idp.sqlite3` (users, sites, codes, tokens), `signing-key.json` (RSA key for ID tokens), `session-secret` |
| `shared` | client secrets made by the provider, mounted read-only into the gate |
| `gate-data` | the gate's cookie-encryption passphrase |

Back up `idp-data`. Set `DATABASE_URL` (any SQLAlchemy URL) on the `idp` service to use another database instead of SQLite.

## Not done yet

- Passkeys / WebAuthn and TOTP second factor
- Rate limiting beyond a one-second delay after a wrong password
- Signing-key rotation (one key, kept until you delete `signing-key.json`)
- A consent screen (sites are registered by the admin, so signing in is the consent)

## License

GPL-3.0, see [LICENSE](LICENSE).
