# Acme Identity agent guide

Acme Identity is the thin local identity layer for the Acme suite. It owns users, manageable roles, sessions, service tokens, and the `acme.principal.v1` contract. It is not a knowledge product and not part of the Prelude → Helix → Issues → Projects workflow line — those apps (and Primer) **consume** it.

**Repo:** [github.com/eimg/acme-identity](https://github.com/eimg/acme-identity)

## Related projects

| Project | Local path | Responsibility |
|---|---|---|
| Acme Identity | `~/Desktop/acme/acme-identity` | Users, roles, sessions, service tokens, principal resolution |
| Primer | `~/Desktop/acme/primer` | Knowledge product; will resolve actors via identity (**integrate last**) |
| Prelude | `~/Desktop/acme/prelude` | Inception drafting; **first** consumer of identity |
| Helix | `~/Desktop/acme/helix` | Workflow control plane; consumer of identity |
| Acme Issues | `~/Desktop/acme/acme-issues` | Issues / local PRs; consumer of identity |
| Acme Projects | `~/Desktop/acme/acme-projects` | Feature board; consumer of identity |

## Product boundaries

- Own **suite identity** (who is acting) and **suite roles** (admin / operator / member / viewer + custom).
- Do **not** own Primer evidence ACL / groups, Issues project membership rules, or Helix run policy — those stay in each product using the principal.
- Keep a stable principal port (`sub`, `iss`, `roles`, `permissions`, `kind`, `authMode`) so a future OIDC adapter can replace the local login adapter.
- Support `ACME_AUTH_MODE=off` so sibling feature tests default to an admin principal without credentials.
- Machine edges use service tokens (Bearer), not browser cookies. Webhook HMAC stays per integration edge for now.

## Architecture

- Node.js 20.19+, TypeScript, ESM.
- Express serves a React/Vite manage UI.
- SQLite at `data/identity.db` (`ACME_IDENTITY_DATA_DIR`).
- Default port **8317**.
- Passwords and service tokens use `scrypt` via `node:crypto` (no extra auth libraries).

## Key modules

| Path | Role |
|---|---|
| `src/types.ts` | `Principal`, roles, auth mode constants |
| `src/client.ts` | Consumer helper exported as `acme-identity/client` |
| `src/principal.ts` | Dev admin principal, permission helpers |
| `src/seed.ts` | Builtin roles, users, permission vocabulary |
| `src/app.ts` | HTTP API + manage UI shell |
| `docs/principal-contract.md` | `acme.principal.v1` field reference |
| `docs/integration.md` | How sibling apps should integrate |

## Working rules

1. Prefer adapter-style identity: apps depend on principals, not password tables.
2. Builtin roles may be edited but not deleted.
3. In `off` mode, anonymous `/api/principal` must resolve as admin (`kind: "dev"`).
4. Do not require Primer (or any workflow app) to be running for identity to work.
5. Gate consumer routes with **permission strings** where possible so custom roles (`dev`, `pm`, …) work without code changes.
6. Before committing cross-cutting changes, run `npm run verify`.
