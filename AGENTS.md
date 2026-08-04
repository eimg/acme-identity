# Acme Identity agent guide

Acme Identity is the thin local identity layer for the Acme suite. It owns users, manageable roles, sessions, service tokens, and the `acme.principal.v1` contract. It is not a knowledge product and not a step in either suite workflow path (new-project or Projects → Issues → Helix); those apps (and Primer) **consume** it.

Treat the Acme suite as an executable reference architecture, not a universal platform. Preserve Identity's local operation, focused ownership, and replaceable public seam; add breadth to demonstrate this responsibility, not to anticipate every organization's identity system.

**Repo:** [github.com/eimg/acme-identity](https://github.com/eimg/acme-identity)

## Related projects

| Project | Local path | Responsibility |
|---|---|---|
| Acme Identity | `~/Desktop/acme/acme-identity` | Users, roles, sessions, service tokens, principal resolution |
| Primer | `~/Desktop/acme/primer` | Knowledge product; resolves Identity principals to Primer-owned actors and groups |
| Prelude | `~/Desktop/acme/prelude` | Inception drafting; optional Identity adapter and delegated Primer auth |
| Helix | `~/Desktop/acme/helix` | Workflow control plane; consumer of identity |
| Acme Issues | `~/Desktop/acme/acme-issues` | Issues / local PRs; consumer of identity |
| Acme Projects | `~/Desktop/acme/acme-projects` | Feature board; consumer of identity |
| Acme Observability | `~/Desktop/acme/acme-obs` | Privileged operational projection; consumer of identity |
| Acme Steering | `~/Desktop/acme/acme-steering` | Decision inbox and delegation-policy coordinator; consumer of identity and scoped service principals |
| Acme Intel | `~/Desktop/acme/acme-intel` | Think-lab for studying suite experience; consumer of identity (admin-operated human access for now) |

## Product boundaries

- Own **suite identity** (who is acting) and **suite roles** (admin / operator / member / viewer + custom).
- Do **not** own Primer evidence ACL / groups, Issues project membership rules, or Helix run policy — those stay in each product using the principal.
- Do **not** own Steering policy, cases, risk classification, or workflow decisions. Identity authenticates actors and service edges only.
- Do **not** own Intel study runs, findings, or publish paths. Identity authenticates Intel operators; Intel keeps domain authorization on `intel.*`.
- Keep a stable principal port (`sub`, `iss`, `roles`, `permissions`, `kind`, `authMode`) so a future OIDC adapter can replace the local login adapter. Contract changes are **additive only**.
- Support `ACME_AUTH_MODE=off` so sibling feature tests default to an admin principal without credentials.
- Machine edges use narrowly scoped service tokens (Bearer), not browser cookies. Calling products must bind those credentials to configured trusted destination origins; Identity owns principals and token lifecycle, not integration routing.

## Architecture

- Node.js 20.19+, TypeScript, ESM.
- Express serves a React/Vite manage UI.
- SQLite at `data/identity.db` (`ACME_IDENTITY_DATA_DIR`), upgraded by an append-only migration list keyed to `PRAGMA user_version`.
- Default port **8316**.
- `node:crypto` only, no extra auth libraries. Passwords use `scrypt`; service tokens are 384-bit random values stored as an unsalted SHA-256 digest, so resolving one is a single indexed lookup with no KDF work on the request path.

## Key modules

| Path | Role |
|---|---|
| `src/types.ts` | `Principal`, roles, auth mode constants |
| `src/permissions.ts` | Permission matching shared with consumers — the only copy |
| `src/client.ts` | Consumer helper exported as `acme-identity/client` |
| `src/principal.ts` | Principal construction, dev/off-mode principals |
| `src/http.ts` | Cookies, origin guard, CORS, login throttle, JSON errors |
| `src/seed.ts` | Builtin roles, users, permission vocabulary |
| `src/store.ts` | SQLite reads/writes, lockout and session invariants |
| `src/app.ts` | HTTP API + manage UI shell |
| `docs/principal-contract.md` | `acme.principal.v1` field reference |
| `docs/integration.md` | How sibling apps should integrate |
| `docs/operations.md` | Configuration, recovery, and known gaps |

## Working rules

1. Prefer adapter-style identity: apps depend on principals, not password tables.
2. Builtin roles may be edited but not deleted, and the `admin` role's permissions stay pinned to `*`.
3. In `off` mode, anonymous `/api/principal` must resolve as admin (`kind: "dev"`). `x-acme-dev-user` may name another seeded user; an unknown name is an error, never a fallback to admin.
4. Do not require Primer (or any workflow app) to be running for identity to work — and do not require identity to be running for a consumer's `off`-mode tests.
5. Gate routes with **permission strings** via `src/permissions.ts` so custom roles (`dev`, `pm`, …) work without code changes. Never reimplement matching, here or in a consumer.
6. No edit may leave identity unadministrable: every write path re-checks that an active user still holds `identity.admin`, and recovery is always possible from the CLI.
7. Keep credential resolution off the KDF path. It runs on every request of every consumer.
8. Every `/api` response is JSON, including errors.
9. Before committing cross-cutting changes, run `npm run verify`.
