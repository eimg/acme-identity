# Acme Identity

Thin local identity layer for the Acme suite: users, manageable roles, sessions, service tokens, and a stable principal contract sibling apps can resolve.

**Default port:** [http://127.0.0.1:8317](http://127.0.0.1:8317) · **Repo:** [github.com/eimg/acme-identity](https://github.com/eimg/acme-identity)

## Acme development testbed

Acme Identity is a cross-cutting service. Workflow and knowledge apps consume it; it does not sit on the Prelude → Helix → Issues → Projects runtime path.

| Project | Role |
|---|---|
| **[Acme Identity](https://github.com/eimg/acme-identity)** | Suite auth: users, roles, sessions, service tokens, `acme.principal.v1` |
| **[Prelude](https://github.com/eimg/prelude)** | Project inception; first planned consumer |
| **[Helix](https://github.com/eimg/helix)** | Agent workflow control plane |
| **[Acme Issues](https://github.com/eimg/acme-issues)** | Issue and local PR lifecycle |
| **[Acme Projects](https://github.com/eimg/acme-projects)** | Feature-idea board |
| **[Primer](https://github.com/eimg/primer)** | Knowledge product; integrate **last** (groups/ACL stay in Primer) |

See [`docs/integration.md`](./docs/integration.md) for consumer wiring and rollout order.

## Auth modes

| Mode | Env | Behavior |
|---|---|---|
| `off` | `ACME_AUTH_MODE=off` | Every caller resolves as **admin** (dev principal). Use for feature tests across Prelude / Helix / Issues / Projects / Primer without signing in. Requires `ACME_ALLOW_INSECURE=1`, `ACME_IDENTITY_DEV=1`, or `NODE_ENV=test`. |
| `local` | `ACME_AUTH_MODE=local` (server default) | Real username/password sessions and Bearer service tokens. |

Sibling apps should default consumers to `off` so local feature work stays unblocked; flip to `local` when exercising multi-user behavior.

## Seeded roles

| Slug | Intent |
|---|---|
| `admin` | Full suite + identity management (`*`) |
| `operator` | Trigger Helix, merge, write boards/issues |
| `member` | Write inception/issues/boards; Primer ask |
| `viewer` | Read-only |

Roles are editable (permissions/name/description). Builtin roles cannot be deleted. Custom roles can be created in the manage UI.

## Seeded users

Password equals username for local development:

- `admin` / `admin`
- `operator` / `operator`
- `member` / `member`
- `viewer` / `viewer`

## Quick start

```bash
cd acme-identity
npm install
npm run dev
```

Open [http://127.0.0.1:8317](http://127.0.0.1:8317).

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
| `GET` | `/api/meta` | Issuer, mode, role catalog |
| `POST` | `/api/session` | Login `{ username, password }` → HttpOnly cookie |
| `GET` | `/api/session` | Current principal / user |
| `DELETE` | `/api/session` | Sign out |
| `GET` | `/api/principal` | Resolve principal (cookie or `Authorization: Bearer`) |
| `POST` | `/api/introspect` | `{ token }` → `{ active, principal? }` |
| `GET/POST` | `/api/roles` | List / create roles |
| `PATCH/DELETE` | `/api/roles/:id` | Update / delete (non-builtin) |
| `GET/POST` | `/api/users` | List / create users |
| `GET/PATCH/DELETE` | `/api/users/:id` | Read / update / delete |
| `GET/POST` | `/api/tokens` | List / mint service tokens |
| `DELETE` | `/api/tokens/:id` | Revoke |

Principal contract: `acme.principal.v1` — see [`docs/principal-contract.md`](./docs/principal-contract.md).

## Consumer helper

```ts
import { resolvePrincipal, defaultConsumerAuthMode } from "acme-identity/client";

const principal = await resolvePrincipal({
  authMode: defaultConsumerAuthMode(), // defaults to off
  cookie: request.headers.cookie,
  authorization: request.headers.authorization,
});
```

In `off` mode the helper returns admin even if identity is unreachable.

## Documentation

| Doc | Contents |
|---|---|
| [`AGENTS.md`](./AGENTS.md) | Agent working rules and module map |
| [`docs/integration.md`](./docs/integration.md) | Sibling app integration, permissions, rollout |
| [`docs/principal-contract.md`](./docs/principal-contract.md) | `acme.principal.v1` reference |

## Scripts

```bash
npm run dev       # serve + Vite HMR on :8317
npm test
npm run verify    # typecheck, test, build
```

## Data

SQLite at `./data/identity.db` (override with `ACME_IDENTITY_DATA_DIR`).
