import type Database from "better-sqlite3";
import { getUserByUsername, permissionsForRoles } from "./store.js";
import type { AuthMode, Principal, User } from "./types.js";
import { ISSUER } from "./types.js";

export {
  grants,
  hasAllPermissions,
  hasAnyPermission,
  hasPermission,
  hasRole,
  isSuiteAdmin,
} from "./permissions.js";

export class UnknownDevUserError extends Error {
  readonly status = 400;
}

export function principalFromUser(
  db: Database.Database,
  user: User,
  authMode: AuthMode,
): Principal {
  return {
    schemaVersion: "acme.principal.v1",
    sub: `user:${user.id}`,
    iss: ISSUER,
    username: user.username,
    displayName: user.displayName,
    email: user.email,
    roles: user.roleSlugs,
    permissions: permissionsForRoles(db, user.roleSlugs),
    kind: "user",
    authMode,
  };
}

export function principalFromService(
  db: Database.Database,
  input: { id: number; name: string; roleSlugs: string[] },
  authMode: AuthMode,
): Principal {
  return {
    schemaVersion: "acme.principal.v1",
    sub: `service:${input.id}`,
    iss: ISSUER,
    username: input.name,
    displayName: input.name,
    email: "",
    roles: input.roleSlugs,
    permissions: permissionsForRoles(db, input.roleSlugs),
    kind: "service",
    authMode,
  };
}

/** Deterministic admin principal for ACME_AUTH_MODE=off across the suite. */
export function devAdminPrincipal(db: Database.Database, _authMode: AuthMode = "off"): Principal {
  const admin = getUserByUsername(db, "admin");
  if (admin) {
    return {
      ...principalFromUser(db, admin, "off"),
      kind: "dev",
      sub: "dev:admin",
      roles: ["admin"],
      permissions: ["*"],
      authMode: "off",
    };
  }
  return {
    schemaVersion: "acme.principal.v1",
    sub: "dev:admin",
    iss: ISSUER,
    username: "admin",
    displayName: "Acme Admin",
    email: "admin@acme.local",
    roles: ["admin"],
    permissions: ["*"],
    kind: "dev",
    authMode: "off",
  };
}

/**
 * Off-mode principal for a named seeded user, so sibling apps can exercise
 * viewer/member/operator gates in their default test mode without passwords.
 * Unknown names throw rather than silently falling back to admin, which would
 * turn a typo into a test that passes for the wrong reason.
 */
export function devPrincipalFor(db: Database.Database, username: string): Principal {
  const wanted = username.trim();
  if (!wanted || wanted === "admin") return devAdminPrincipal(db);
  const user = getUserByUsername(db, wanted);
  if (!user) throw new UnknownDevUserError(`Unknown dev principal: ${wanted}`);
  return {
    ...principalFromUser(db, user, "off"),
    kind: "dev",
    sub: `dev:${user.username}`,
    authMode: "off",
  };
}
