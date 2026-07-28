import type Database from "better-sqlite3";
import { getUserByUsername, permissionsForRoles } from "./store.js";
import type { AuthMode, Principal, User } from "./types.js";
import { ISSUER } from "./types.js";

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

export function hasPermission(principal: Principal, permission: string): boolean {
  if (principal.permissions.includes("*")) return true;
  if (principal.roles.includes("admin")) return true;
  return principal.permissions.includes(permission);
}

export function hasRole(principal: Principal, role: string): boolean {
  return principal.roles.includes(role) || principal.roles.includes("admin");
}
