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

In **`off`**, an anonymous caller is treated as admin (`kind: "dev"`, `sub: "dev:admin"`). The consumer helper answers this **without a network call**, so a sibling app's feature tests never need identity running. A caller that presents a real credential is still resolved against identity, so role behaviour can be exercised in either mode.

## Consumer integration pattern

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
| `ACME_IDENTITY_URL` | `http://127.0.0.1:8317` | Identity base URL |
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
| `helix.read` / `helix.trigger` / `helix.merge` | Helix surfaces |
| `issues.read` / `issues.write` | Acme Issues |
| `projects.read` / `projects.write` | Acme Projects |
| `primer.ask` | Primer grounded chat (ACL still enforced inside Primer) |

Products may gate on keys not in this list (`primer.evidence.read`); they are accepted as long as they match the shape. Custom roles (`dev`, `pm`, …) are created in the manage UI by assigning permission subsets — no code change required if gates use permission strings.

## Rollout order (planned)

1. **Prelude** — first consumer; export/context/discussion gates
2. **Helix** — run trigger / manage surfaces
3. **Acme Issues** — issue/PR mutations; keep webhook HMAC separate
4. **Acme Projects** — board writes
5. **Primer** — last; map principal → fixture actor; groups stay in Primer

When integrating an app, update that app's `AGENTS.md` related-projects table to list Acme Identity.

## Machine / webhook auth

Browser sessions are for humans. Service-to-service edges (Issues ↔ Helix ↔ Projects) should use **service tokens** minted in the manage UI or with `acme-identity mint-token`, passed as `Authorization: Bearer svc_…`. Tokens can carry an expiry; a token is shown once at creation and stored only as a digest.

Webhook HMAC remains per-link configuration until a suite-wide machine-auth pass lands. Do not authenticate webhooks with browser cookies.

## Calling identity from a browser

Identity does **not** send CORS headers by default, because the normal pattern is server-side resolution. Cross-origin **writes are rejected** even though `SameSite=Lax` would attach the cookie: every suite app is on another port of the same host, so `localhost:8321` is same-site with `localhost:8317` and would otherwise be able to drive authenticated writes.

To call identity directly from a sibling app's frontend, list its origin:

```bash
ACME_IDENTITY_ALLOWED_ORIGINS=http://localhost:8321,http://localhost:8319
```

That enables credentialed CORS for those origins and exempts them from the write guard.

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

Run consumer feature tests with `ACME_AUTH_MODE=off` (default). Add auth-specific tests that resolve as `viewer` / `member` / `admin` and assert 403/200 on gated routes — with `devUser` in off mode, or real sign-in in `local`.
