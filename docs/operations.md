# Operating Acme Identity

Identity is local-first and deliberately small, but it is the one service in the suite whose failure or compromise affects everything else. This is what to know when running it somewhere other than a laptop, and how to get back in when locked out.

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `ACME_IDENTITY_DATA_DIR` | `./data` | SQLite location (`identity.db`) |
| `ACME_AUTH_MODE` | `local` | `off` resolves every caller as a dev principal |
| `ACME_ALLOW_INSECURE` | unset | Required to start in `off` mode outside test/dev |
| `ACME_DEV_PRINCIPAL` | `admin` | Off mode: seeded user anonymous callers resolve as |
| `ACME_IDENTITY_ADMIN_PASSWORD` | unset | Admin password used when the database is **first seeded** |
| `ACME_IDENTITY_ALLOWED_ORIGINS` | unset | Origins allowed to call the API from a browser (enables credentialed CORS) |
| `ACME_IDENTITY_COOKIE_SECURE` | auto | `1`/`0` to force the session cookie `Secure` flag; auto follows the request scheme |
| `ACME_IDENTITY_TRUST_PROXY` | unset | Set to `1` behind a reverse proxy so client IP and scheme come from `X-Forwarded-*` |
| `PORT` | `8316` | Default port |

## Before exposing it beyond loopback

The seeded accounts use their username as the password, which is right for local development and wrong for anything else.

1. Seed with a real admin password: `ACME_IDENTITY_ADMIN_PASSWORD=… npm start` on a fresh data directory, or `acme-identity set-password admin` afterwards.
2. Terminate TLS in front of it and set `ACME_IDENTITY_TRUST_PROXY=1`, so the session cookie is marked `Secure` and login throttling sees real client IPs.
3. Rotate or disable the other seeded accounts (`operator`, `member`, `viewer`).

The server prints a warning on startup if it is bound to a non-loopback address while the seeded admin password is still in place.

## Recovery

Every recovery path is local and needs no working session, so a lost admin password is never terminal. These commands operate on the SQLite file directly and are safe to run while the server is up.

```bash
acme-identity list-users
echo 'new-password' | acme-identity set-password admin   # revokes that user's sessions
acme-identity mint-token ci-issues-writer svc-projects-to-issues --expires-in-days 30
acme-identity list-tokens
```

Identity also refuses edits that would leave nobody able to administer it: you cannot delete, disable, or demote the last active user holding `identity.admin`, and the builtin `admin` role's permissions are pinned to `*`. Those checks run inside the write transaction, so a rejected edit changes nothing.

## Sessions and tokens

- Sessions last 14 days, are stored server-side, and are revoked on password change and on user deactivation. Expired rows are swept on startup and on each login.
- `DELETE /api/users/:id/sessions` signs a user out everywhere. The manage UI exposes it as **Sign out** on the users tab.
- Service tokens are shown once at creation and stored as a SHA-256 digest, so a leaked database does not yield usable tokens. Prefer an expiry for machine edges.
- `npm run provision:suite-auth` creates or updates five least-privilege machine
  roles, atomically rotates their tokens into sibling ignored `.env` files,
  applies a 90-day expiry by default, and sets those files to mode `0600`.
- Failed logins are throttled per username and client IP (10 failures per 15 minutes) and answered with `429` plus `Retry-After`. The counter is in memory, so a restart clears it.

## Backups

The whole state is `data/identity.db` plus its WAL sidecar. Back it up with `sqlite3 identity.db ".backup out.db"` rather than copying the file while the server runs. Schema upgrades are applied automatically on open from an append-only migration list keyed to `PRAGMA user_version`, so restoring an older file into a newer build works.

## What is intentionally absent

Called out so nobody assumes these exist:

- **No audit log.** Who changed a role, and when, is not recorded beyond `updatedAt`.
- **No rate limiting outside login.** A local caller can hammer `/api/principal`.
- **No CSP on the manage UI**, and its assets are served from the same origin as the API.
- **No multi-process story.** SQLite with WAL and one writer is the assumption; run one identity process.
- **No password policy** beyond non-empty, since seeded development credentials are deliberately trivial.

See the pull request that introduced this document for the reasoning on each.
