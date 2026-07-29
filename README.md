# Acme Identity

Thin local identity layer for the Acme suite: users, manageable roles, sessions, service tokens, and a stable principal contract sibling apps can resolve.

**Default port:** [http://127.0.0.1:8316](http://127.0.0.1:8316) · **Repo:** [github.com/eimg/acme-identity](https://github.com/eimg/acme-identity)

## Acme development testbed

Acme Identity is a cross-cutting service. Workflow and knowledge apps consume it; it does not sit on the Prelude → Helix → Issues → Projects runtime path.

| Project | Role |
|---|---|
| **[Acme Identity](https://github.com/eimg/acme-identity)** | Suite auth: users, roles, sessions, service tokens, `acme.principal.v1` |
| **[Prelude](https://github.com/eimg/prelude)** | Project inception; optional Identity adapter and delegated Primer auth |
| **[Helix](https://github.com/eimg/helix)** | Agent workflow control plane |
| **[Acme Issues](https://github.com/eimg/acme-issues)** | Issue and local PR lifecycle |
| **[Acme Projects](https://github.com/eimg/acme-projects)** | Feature-idea board |
| **[Primer](https://github.com/eimg/primer)** | Knowledge product; Identity gates operations while groups/ACL stay in Primer |

See [`docs/integration.md`](./docs/integration.md) for consumer wiring and the current integration map.

## Auth modes

| Mode | Env | Behavior |
|---|---|---|
| `off` | `ACME_AUTH_MODE=off` | Callers resolve as **admin** (dev principal). Use for feature tests across Prelude / Helix / Issues / Projects / Primer without signing in. Requires `ACME_ALLOW_INSECURE=1`, `ACME_IDENTITY_DEV=1`, or `NODE_ENV=test`. |
| `local` | `ACME_AUTH_MODE=local` (server default) | Real username/password sessions and Bearer service tokens. |

Sibling apps should default consumers to `off` so local feature work stays unblocked; flip to `local` when exercising multi-user behavior. In `off` mode the consumer helper answers anonymous callers locally, so sibling tests do not need identity running at all.

To exercise a non-admin gate while still in `off` mode, name a seeded user:

```bash
curl -H 'x-acme-dev-user: viewer' http://127.0.0.1:8316/api/principal
```

## Seeded roles

| Slug | Intent |
|---|---|
| `admin` | Full suite + identity management (`*`) |
| `operator` | Read/trigger/review/bootstrap Helix, merge, write boards/issues |
| `member` | Write inception/issues/boards; Primer ask |
| `viewer` | Read-only |

Roles are editable (permissions/name/description). Builtin roles cannot be deleted, and the `admin` role keeps `*` so identity can never be locked out. Custom roles are created in the manage UI by picking permissions from the vocabulary published at `/api/meta`.

Permissions match exactly (`prelude.write`), by namespace (`prelude.*`), or globally (`*`).

## Seeded users

Password equals username for local development:

- `admin` / `admin`
- `operator` / `operator`
- `member` / `member`
- `viewer` / `viewer`

The local seed also provisions the nine human Primer fixture accounts using
their email local-part as both username and initial development password (for
example `maya.chen` / `maya.chen`). Their exact emails let Primer establish a
stable Identity-subject-to-existing-actor mapping on first use. Change these
development passwords before using the suite beyond loopback.

Set `ACME_IDENTITY_ADMIN_PASSWORD` before the first run to seed a real admin password, or run `acme-identity set-password admin` later. See [`docs/operations.md`](./docs/operations.md) before binding to anything but loopback.

For the local sibling checkout, `npm run provision:suite-auth` rotates five
origin-bound, least-privilege machine tokens into the ignored service `.env`
files. Tokens expire after 90 days unless `ACME_SERVICE_TOKEN_DAYS` is set.

## Quick start

```bash
cd acme-identity
npm install
npm run dev
```

Open [http://127.0.0.1:8316](http://127.0.0.1:8316).

The local suite shares one host-only `acme_identity_session` cookie across its
ports. Sign in through any Identity-backed browser app and the other apps on the
same hostname resolve the same principal; signing out invalidates that central
session everywhere. Use one hostname consistently (`127.0.0.1` and `localhost`
are different cookie hosts). See [`docs/integration.md`](./docs/integration.md)
for the trust boundary and production guidance.

```bash
# Real local auth
ACME_AUTH_MODE=local npm run dev

# Explicit off mode (admin for everyone)
ACME_AUTH_MODE=off ACME_ALLOW_INSECURE=1 npm run dev
```

## API surface

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/health` | Liveness + mode |
| `GET` | `/api/meta` | Issuer, mode, role catalog, permission vocabulary, cookie name |
| `POST` | `/api/session` | Login `{ username, password }` → HttpOnly cookie (throttled) |
| `GET` | `/api/session` | Current principal / user |
| `DELETE` | `/api/session` | Sign out |
| `POST` | `/api/session/password` | Self-service `{ currentPassword, newPassword }`; revokes all sessions |
| `GET` | `/api/principal` | Resolve principal (cookie or `Authorization: Bearer`) |
| `POST` | `/api/introspect` | `{ token }` → `{ active, principal? }`; needs `identity.read` |
| `GET/POST` | `/api/roles` | List / create roles |
| `PATCH/DELETE` | `/api/roles/:id` | Update / delete (non-builtin) |
| `GET/POST` | `/api/users` | List / create users |
| `GET/PATCH/DELETE` | `/api/users/:id` | Read / update / delete |
| `GET/DELETE` | `/api/users/:id/sessions` | Count / revoke a user's sessions |
| `GET/POST` | `/api/tokens` | List / mint service tokens (optional `expiresInDays`) |
| `DELETE` | `/api/tokens/:id` | Revoke |

Every `/api` response is JSON, including 404s and unexpected errors, so consumers never have to parse an HTML error page. Cross-origin writes are rejected unless the origin is in `ACME_IDENTITY_ALLOWED_ORIGINS`.

The manage UI accepts `/?tab=account` as a direct link to the signed-in user's
account. Replaceable consumer adapters may expose that URL as optional session
metadata; browser components should not hardcode an Identity deployment URL.

Principal contract: `acme.principal.v1` — see [`docs/principal-contract.md`](./docs/principal-contract.md).

## Consumer helper

```ts
import { hasPermission, resolvePrincipal } from "acme-identity/client";

const principal = await resolvePrincipal({
  cookie: request.headers.cookie,
  authorization: request.headers.authorization,
});

if (!hasPermission(principal, "prelude.write")) throw new Error("forbidden");
```

In `off` mode the helper returns admin even if identity is unreachable. Gate on permissions using the exported matchers rather than reimplementing them — that is the one copy shared by all five consumers. `IdentityClientError.code` distinguishes `unauthenticated` (401) from `unavailable` (503), so an identity outage is never mistaken for a signed-out user.

## Documentation

| Doc | Contents |
|---|---|
| [`AGENTS.md`](./AGENTS.md) | Agent working rules and module map |
| [`docs/integration.md`](./docs/integration.md) | Sibling app integration, permissions, and current consumer status |
| [`docs/principal-contract.md`](./docs/principal-contract.md) | `acme.principal.v1` reference |
| [`docs/operations.md`](./docs/operations.md) | Configuration, recovery, and known gaps |

## Scripts

```bash
npm run dev       # serve + Vite HMR on :8316
npm test
npm run verify    # typecheck, test, build
```

## CLI

```bash
acme-identity serve [--port n] [--host h] [--mode off|local]
acme-identity list-users
acme-identity set-password <username>    # reads from stdin; recovery path
acme-identity mint-token <name> <roles> [--expires-in-days n]
acme-identity list-tokens
```

## Data

SQLite at `./data/identity.db` (override with `ACME_IDENTITY_DATA_DIR`). Schema upgrades apply on open from an append-only migration list keyed to `PRAGMA user_version`.
