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
| `kind` | `user` (interactive), `service` (Bearer token), `dev` (`off` mode admin) |
| `authMode` | `off` or `local` — how this principal was resolved |

## Resolution

| Transport | Use |
|---|---|
| HttpOnly cookie `acme_identity_session` | Browser UI sessions after `POST /api/session` |
| `Authorization: Bearer <token>` | Service tokens (`svc_…`) or session id for API clients |
| `GET /api/principal` | Canonical lookup for sibling apps |
| `POST /api/introspect` `{ "token": "…" }` | Token validation without forwarding cookies |

## Permission checks in consumers

```ts
function hasPermission(principal: Principal, permission: string): boolean {
  return (
    principal.permissions.includes("*") ||
    principal.roles.includes("admin") ||
    principal.permissions.includes(permission)
  );
}
```

Prefer **permission strings** (`prelude.write`, `issues.read`) over hard-coding role slugs in route handlers. Roles are manageable; permissions are the stable gate vocabulary.

## What identity does not own

- Primer evidence ACL / groups — stay in Primer
- Issues project membership — stay in Issues
- Helix run policy — stay in Helix
- Webhook HMAC secrets — per integration edge (may use service principals later)

## Future adapters

A third-party IdP should still emit `acme.principal.v1`. Map external `sub` + group claims into suite `roles` / `permissions` in one adapter layer; do not leak IdP-specific types into product code.
