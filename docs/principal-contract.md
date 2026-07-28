# Principal contract (`acme.principal.v1`)

**Status:** Shipped by Acme Identity. Sibling apps should depend on this shape, not on identity storage or password tables.

Acme Identity resolves **who is acting** (human user, service token, or dev principal). Each product still owns **what they may do** in its domain using `roles` and `permissions` from the principal.

## Shape

```json
{
  "schemaVersion": "acme.principal.v1",
  "sub": "user:1",
  "iss": "acme-identity",
  "username": "admin",
  "displayName": "Acme Admin",
  "email": "admin@acme.local",
  "roles": ["admin"],
  "permissions": ["*"],
  "kind": "user",
  "authMode": "local"
}
```

| Field | Meaning |
|---|---|
| `sub` | Stable subject id. Prefix indicates kind: `user:`, `service:`, `dev:` |
| `iss` | Issuer. Today always `acme-identity`; reserved for future OIDC adapters |
| `username` | Login name or service token name |
| `displayName` | Human-readable label |
| `email` | Optional email (empty for service principals) |
| `roles` | Suite role slugs assigned to this principal |
| `permissions` | Flattened permission strings from all roles (`*` = all) |
| `kind` | `user` (interactive), `service` (Bearer token), `dev` (`off` mode principal) |
| `authMode` | `off` or `local` — how this principal was resolved |

### Compatibility rule

Changes to this contract are **additive only**, and consumers must **ignore fields they do not know** rather than validating exhaustively. That is what lets identity add a field without a coordinated release across five apps. `schemaVersion` only changes if an existing field changes meaning.

## Resolution

| Transport | Use |
|---|---|
| HttpOnly cookie `acme_identity_session` | Browser UI sessions after `POST /api/session` |
| `Authorization: Bearer svc_…` | Service tokens |
| `Authorization: Bearer sess_…` | Session id for API clients that cannot hold cookies |
| `GET /api/principal` | Canonical lookup for sibling apps |
| `POST /api/introspect` `{ "token": "…" }` | Token validation without forwarding cookies. **Requires the caller to authenticate** with `identity.read` |

Resolution is a couple of indexed SQLite reads, with no key-derivation work on the request path, so calling `/api/principal` per request is the intended pattern. Do not cache principals in consumers: a revoked token or a disabled user must take effect immediately.

## Permission checks in consumers

Do not reimplement matching. Import it:

```ts
import { hasPermission, hasAnyPermission } from "acme-identity/client";

if (!hasPermission(principal, "prelude.export")) return res.status(403).json({ error: "forbidden" });
```

Grant forms, narrowest to widest:

| Grant | Matches |
|---|---|
| `prelude.write` | exactly `prelude.write` |
| `prelude.*` | every key in the `prelude` namespace, including nested (`primer.evidence.read` for `primer.*`) |
| `*` | everything; held by the builtin `admin` role |

`hasRole` is **exact** membership with no implicit admin bypass, so a role check and a permission check never disagree about the same principal. The `admin` role holds `*` and its permission set is pinned, so admins still pass every permission check. Prefer **permission strings** over role slugs: roles are manageable, permissions are the stable gate vocabulary.

Consumers should surface a missing permission as **403** and an unresolvable principal as **401** — except when identity itself is unreachable, which is **503**:

```ts
import { IdentityClientError, resolvePrincipal } from "acme-identity/client";

try {
  const principal = await resolvePrincipal({ cookie: req.headers.cookie });
} catch (error) {
  if (error instanceof IdentityClientError && error.code === "unavailable") {
    return res.status(503).json({ error: "Identity unavailable" });
  }
  return res.status(401).json({ error: "Authentication required" });
}
```

Treating an outage as "signed out" would show every user a login screen they cannot complete.

## What identity does not own

- Primer evidence ACL / groups — stay in Primer
- Issues project membership — stay in Issues
- Helix run policy — stay in Helix
- Service routing and trusted destination origins — configured by each calling product; Identity supplies scoped bearer principals but never decides where a credential may be sent

## Future adapters

A third-party IdP should still emit `acme.principal.v1`. Map external `sub` + group claims into suite `roles` / `permissions` in one adapter layer; do not leak IdP-specific types into product code. Because consumers only ever see this shape and only ever call `resolvePrincipal`, swapping the local login adapter for OIDC should not touch product route handlers.
