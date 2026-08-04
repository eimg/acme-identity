# Integrating sibling apps with Acme Identity

**Status:** Acme Identity and consumer adapters are shipped across Prelude, Helix, Acme Issues, Acme Projects, and Primer. Each product remains independently runnable with its standalone/off adapter. Suite operators should also read the root README **Suite authentication glossary** (`ACME_AUTH_MODE` vs `*_AUTH_PROVIDER`).

## Suite placement

```text
Identity (this repo)     who is acting / suite roles / scoped service tokens
New-project path         Primer (optional evidence) → Prelude → Helix bootstrap
Existing-project path    Projects → Issues → Helix → human merge
Knowledge                Primer (cross-cutting; separate from the Issues → Helix loop)
```

Workflow apps must **not** depend on Primer for login. Primer consumes identity like everyone else.

## Auth modes

| Mode | Server default | Consumer default | When to use |
|---|---|---|---|
| `off` | requires `ACME_ALLOW_INSECURE=1` or test/dev | `ACME_AUTH_MODE=off` (unset) | Feature tests, local work without sign-in |
| `local` | yes for identity server | set explicitly | Multi-user / role enforcement |

Primer, Prelude, and Helix map the same suite choice through `*_AUTH_PROVIDER=standalone|acme-identity` (plain HTTP to Identity). Issues, Projects, Observability, Steering, and Intel use `ACME_AUTH_MODE` with the Identity client package or equivalent resolver. Keep mode and provider aligned across the suite.

In **`off`**, an anonymous caller is treated as admin (`kind: "dev"`, `sub: "dev:admin"`). The consumer helper answers this **without a network call**, so a sibling app's feature tests never need identity running. A caller that presents a real credential is still resolved against identity, so role behaviour can be exercised in either mode.

## Consumer integration pattern

Two shipped patterns exist today:

1. **Plain-HTTP adapter** (`*_AUTH_PROVIDER`) — Primer, Prelude, Helix. Prefer this when the product must stay independently clonable without a sibling Identity checkout.
2. **`acme-identity` package** — Issues, Projects, and several `acme-*` services. Convenient inside the suite checkout (`file:../acme-identity`).

For new adapters, prefer the HTTP pattern unless you already share the suite layout. Unifying Issues/Projects onto HTTP remains open suite work.

Current package-oriented steps:

1. Add dependency on `acme-identity` (path, npm link, or copy `src/client.ts` patterns).
2. Resolve principal once per request via `resolvePrincipal()`.
3. Attach principal to `res.locals` (or equivalent).
4. Gate routes with **permissions** using the exported matchers — do not reimplement matching.
5. Keep existing tests on `ACME_AUTH_MODE=off`; add a separate auth test file for `local`.

```ts
import {
  hasPermission,
  IdentityClientError,
  resolvePrincipal,
} from "acme-identity/client";

app.use(async (req, res, next) => {
  try {
    res.locals.principal = await resolvePrincipal({
      authorization: req.headers.authorization,
      cookie: req.headers.cookie,
    });
    next();
  } catch (error) {
    const unavailable =
      error instanceof IdentityClientError && error.code === "unavailable";
    res.status(unavailable ? 503 : 401).json({ error: (error as Error).message });
  }
});

app.post("/api/inceptions", (req, res) => {
  if (!hasPermission(res.locals.principal, "prelude.write")) {
    return res.status(403).json({ error: "Missing permission: prelude.write" });
  }
  // …
});
```

Environment:

| Variable | Default | Role |
|---|---|---|
| `ACME_AUTH_MODE` | `off` (consumers) / `local` (identity server) | Auth adapter selection |
| `ACME_IDENTITY_URL` | `http://127.0.0.1:8316` | Identity base URL |
| `ACME_ALLOW_INSECURE` | unset | Required for identity server `off` mode outside test |
| `ACME_DEV_PRINCIPAL` | `admin` | Off mode: which seeded user anonymous callers resolve as |

## Testing role gates without passwords

In `off` mode, `x-acme-dev-user: <username>` resolves as that seeded user, keeping their real roles and permissions with `kind: "dev"`. This is how a consumer asserts 403s in the mode its feature tests already run in:

```ts
// In the consumer's own tests
const viewer = await resolvePrincipal({ authMode: "off", devUser: "viewer" });
```

An unknown name is a **400**, not a fallback to admin — a typo must not turn into a test that passes for the wrong reason. Set `ACME_DEV_PRINCIPAL` to change the default for a whole process.

The header is ignored in `local` mode.

## Permission vocabulary

Permissions use `<product>.<action>`, with `<product>.*` for a whole namespace and `*` for everything. The authoritative list is served from **`GET /api/meta`** (`permissions[]`) and defined in `src/seed.ts`; the manage UI renders it as a picker. Add new suite capabilities there.

| Permission | Typical use |
|---|---|
| `identity.read` | List users/roles, introspect tokens |
| `identity.admin` | Manage users, roles, tokens (the `admin` role grants it via `*`) |
| `prelude.read` | View inceptions |
| `prelude.write` | Edit inceptions, documents, discussions |
| `prelude.export` | Export bootstrap artifacts |
| `prelude.discuss` | Participate in discussions |
| `prelude.context` | Mark discussion topics include-in-context |
| `helix.read` / `helix.trigger` / `helix.review` | Helix run and PR-review surfaces |
| `helix.steering.recover` | Steering-authorized Helix run recovery only |
| `helix.merge` / `helix.bootstrap` | Helix merge and bootstrap actions |
| `helix.manage` / `helix.admin` | Helix authoring and administration |
| `issues.read` / `issues.write` | Acme Issues |
| `projects.read` / `projects.write` | Acme Projects |
| `prelude.steering.receive` / `helix.steering.receive` / `issues.steering.receive` / `projects.steering.receive` | Record a Steering disposition without applying a workflow transition |
| `prelude.steering.export` / `helix.steering.recover` / `issues.steering.trigger` / `projects.steering.submit` | Narrow Steering-to-product action endpoints |
| `steering.notify.prelude` / `.helix` / `.issues` / `.projects` | Product-bound workflow notification publishing |
| `primer.ask` | Primer grounded chat (ACL still enforced inside Primer) |
| `primer.manage` | Primer actors, sources, synchronization, and evaluation |
| `observability.read` | View suite observations, traces, and source health |
| `observability.collect` | Run read-only source collection |
| `observability.manage` | Manage configuration and rebuild derived observations |

Products may gate on keys not in this list (`primer.evidence.read`); they are accepted as long as they match the shape. Custom roles (`dev`, `pm`, …) are created in the manage UI by assigning permission subsets — no code change required if gates use permission strings.

## Current consumer status

1. **Prelude** — permission-gated authoring, discussion, context, and export surfaces; delegates the caller credential to trusted Primer origins only.
2. **Helix** — replaceable human-auth adapter plus permission-gated run, review, merge, bootstrap, manage, and admin surfaces.
3. **Acme Issues** — permission-gated issue/PR operations and scoped service-token callbacks with trusted-destination binding.
4. **Acme Projects** — permission-gated board operations and scoped service-token wiring to Acme Issues.
5. **Primer** — maps the resolved principal to an existing Primer actor; Identity gates operations, while Primer-owned groups and evidence ACLs continue to determine knowledge access.
6. **Acme Observability** — provides a privileged, suite-wide operational projection gated by read, collect, and manage permissions; it does not implement row-level source ACLs.
7. **Acme Steering** — gates inbox reading, decisions, policy management, product-bound notification publishing, decision delivery, and narrow product actions with separate permission strings. Identity does not decide policy outcomes or domain transitions.

When integrating an app, update that app's `AGENTS.md` related-projects table to list Acme Identity.

## Machine / webhook auth

Browser sessions are for humans. Service-to-service edges use **service tokens**
passed as `Authorization: Bearer svc_…`. Give every direction a narrow custom
role, expiry, and separate token; do not reuse the human `operator` role. The
local suite can provision and rotate all nine current edges with `npm run
provision:suite-auth` from Acme Identity. Tokens are shown once and stored only
as digests.

Consumers must bind each token to configured trusted destination origins before
adding the header. A user-editable callback or integration URL must never decide
where a service credential is sent. Do not authenticate webhooks with browser cookies.

## Shared local browser session

The local suite uses one host-only `acme_identity_session` cookie with
`Path=/`, `HttpOnly`, and `SameSite=Lax`. Cookies are scoped by hostname rather
than port, so signing in through one app on `127.0.0.1` makes that session
available to the other suite ports on `127.0.0.1`. Each consumer resolves the
cookie server-side through Identity and applies its own permission gates; it
does not copy user records. Signing out deletes the central session and clears
the shared cookie.

Consumers must proxy browser session writes through their own same-origin API
and reject cross-origin mutations. Use one hostname consistently: `localhost`
and `127.0.0.1` do not share cookies. This is a trusted local-suite convenience,
not a general production SSO topology—a compromised sibling server on the same
host can receive the shared cookie. A deployed replacement should normally use
an OIDC-style provider with per-application sessions.

An auth adapter may optionally publish an account-management URL in its local
session response. The current Identity UI supports `/?tab=account`. Keep this
metadata optional so standalone consumers and future providers remain usable
without Acme-specific browser coupling.

## Calling identity from a browser

Identity does **not** send CORS headers by default, because the normal pattern is server-side resolution. Cross-origin **writes are rejected** even though `SameSite=Lax` would attach the cookie: every suite app is on another port of the same host, so `localhost:8318` is same-site with `localhost:8316` and would otherwise be able to drive authenticated writes.

To call identity directly from a sibling app's frontend, list its origin:

```bash
ACME_IDENTITY_ALLOWED_ORIGINS=http://localhost:8318,http://localhost:8319
```

That enables credentialed CORS for those origins and exempts them from the write guard.

## Local ports (reference)

| App | Port |
|---|---|
| Acme Identity | 8316 |
| Primer | 8317 |
| Prelude | 8318 |
| Helix | 8319 |
| Acme Issues | 8320 |
| Acme Projects | 8321 |

## Verify integration

```bash
# Identity running
ACME_AUTH_MODE=local npm run dev

# Consumer in local mode
ACME_AUTH_MODE=local ACME_IDENTITY_URL=http://127.0.0.1:8316 npm run dev
```

Run consumer feature tests with `ACME_AUTH_MODE=off` (default). Add auth-specific tests that resolve as `viewer` / `member` / `admin` and assert 403/200 on gated routes — with `devUser` in off mode, or real sign-in in `local`.
