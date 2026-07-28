# Integrating sibling apps with Acme Identity

**Status:** Acme Identity is shipped. Consumer integration is rolling out app-by-app. **Prelude is first**; Primer is intentionally **last** (its auth model is the most complex).

## Suite placement

```text
Identity (this repo)     who is acting / suite roles
Workflow                 Prelude → Helix → Issues → Projects
Knowledge                Primer (cross-cutting; absorbs state later)
```

Workflow apps must **not** depend on Primer for login. Primer consumes identity like everyone else.

## Auth modes

| Mode | Server default | Consumer default | When to use |
|---|---|---|---|
| `off` | requires `ACME_ALLOW_INSECURE=1` or test/dev | `ACME_AUTH_MODE=off` (unset) | Feature tests, local work without sign-in |
| `local` | yes for identity server | set explicitly | Multi-user / role enforcement |

In **`off`**, every unresolved caller is treated as admin (`kind: "dev"`, `sub: "dev:admin"`). Sibling apps should still call the identity port so flipping to `local` does not require rewriting handlers.

## Consumer integration pattern

1. Add dependency on `acme-identity` (path, npm link, or copy `src/client.ts` patterns).
2. Resolve principal once per request via `resolvePrincipal()`.
3. Attach principal to `res.locals` (or equivalent).
4. Gate routes with **permissions**, not role names, where possible.
5. Keep existing tests on `ACME_AUTH_MODE=off`; add a separate auth test file for `local`.

```ts
import {
  bearerFromRequest,
  defaultConsumerAuthMode,
  resolvePrincipal,
} from "acme-identity/client";

const principal = await resolvePrincipal({
  authMode: defaultConsumerAuthMode(),
  authorization: req.headers.authorization,
  cookie: req.headers.cookie,
});
```

Environment:

| Variable | Default | Role |
|---|---|---|
| `ACME_AUTH_MODE` | `off` (consumers) / `local` (identity server) | Auth adapter selection |
| `ACME_IDENTITY_URL` | `http://127.0.0.1:8317` | Identity base URL |
| `ACME_ALLOW_INSECURE` | unset | Required for identity server `off` mode outside test |

## Permission vocabulary (seeded)

Permissions use `<product>.<action>`. Products may define finer gates locally; add new permission strings here when introducing new suite capabilities.

| Permission | Typical use |
|---|---|
| `identity.read` | List users/roles (non-admin read) |
| `identity.admin` | Manage users, roles, tokens (admin role also grants via `*`) |
| `prelude.read` | View inceptions |
| `prelude.write` | Edit inceptions, documents, discussions |
| `prelude.export` | Export bootstrap artifacts (admin-only in Prelude rollout) |
| `prelude.discuss` | Participate in discussions (non-viewer) |
| `prelude.context` | Mark discussion topics include-in-context (admin-only in Prelude rollout) |
| `helix.read` / `helix.trigger` / `helix.merge` | Helix surfaces |
| `issues.read` / `issues.write` | Acme Issues |
| `projects.read` / `projects.write` | Acme Projects |
| `primer.ask` | Primer grounded chat (ACL still enforced inside Primer) |

Custom roles (e.g. future `dev`, `pm`) are created in the manage UI by assigning permission subsets — no code change required if gates use permission strings.

## Rollout order (planned)

1. **Prelude** — first consumer; export/context/discussion gates
2. **Helix** — run trigger / manage surfaces
3. **Acme Issues** — issue/PR mutations; keep webhook HMAC separate
4. **Acme Projects** — board writes
5. **Primer** — last; map principal → fixture actor; groups stay in Primer

When integrating an app, update that app's `AGENTS.md` related-projects table to list Acme Identity.

## Machine / webhook auth

Browser sessions are for humans. Service-to-service edges (Issues ↔ Helix ↔ Projects) should use **service tokens** minted in the identity manage UI, passed as `Authorization: Bearer svc_…`.

Webhook HMAC remains per-link configuration until a suite-wide machine-auth pass lands. Do not authenticate webhooks with browser cookies.

## Local ports (reference)

| App | Port |
|---|---|
| Acme Identity | 8317 |
| Primer | 8318 |
| Helix | 8319 |
| Acme Issues | 8320 |
| Prelude | 8321 |
| Acme Projects | 8330 |

## Verify integration

```bash
# Identity running
ACME_AUTH_MODE=local npm run dev

# Consumer in local mode
ACME_AUTH_MODE=local ACME_IDENTITY_URL=http://127.0.0.1:8317 npm run dev
```

Run consumer feature tests with `ACME_AUTH_MODE=off` (default). Add auth-specific tests that sign in as `viewer` / `member` / `admin` and assert 403/200 on gated routes.
