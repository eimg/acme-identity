/**
 * Permission matching. Dependency-free on purpose: this module is the one copy
 * of the matching rules shared by the identity server and every consumer app,
 * and it is re-exported from `acme-identity/client`.
 *
 * Grant forms, narrowest to widest:
 *   prelude.write   exact
 *   prelude.*       every permission in the `prelude` namespace
 *   *               everything (the builtin admin role)
 */

export const WILDCARD = "*";

/** Anything carrying resolved roles + permissions: a Principal, or a role's grant list. */
export interface PermissionHolder {
  roles: readonly string[];
  permissions: readonly string[];
}

const PERMISSION_PATTERN = /^(\*|[a-z0-9][a-z0-9-]*\.(\*|[a-z0-9][a-z0-9.-]*))$/;

export function normalizePermission(value: string): string {
  return value.trim().toLowerCase();
}

/** Shape check only. Unknown-but-well-formed keys stay legal so products can define their own. */
export function isValidPermission(value: string): boolean {
  return PERMISSION_PATTERN.test(normalizePermission(value));
}

export function grants(granted: string, requested: string): boolean {
  if (granted === WILDCARD) return true;
  if (granted === requested) return true;
  if (granted.endsWith(`.${WILDCARD}`)) {
    return requested.startsWith(granted.slice(0, -1));
  }
  return false;
}

export function hasPermission(holder: PermissionHolder, permission: string): boolean {
  const requested = normalizePermission(permission);
  return holder.permissions.some((granted) => grants(granted, requested));
}

export function hasAnyPermission(holder: PermissionHolder, permissions: string[]): boolean {
  return permissions.some((permission) => hasPermission(holder, permission));
}

export function hasAllPermissions(holder: PermissionHolder, permissions: string[]): boolean {
  return permissions.every((permission) => hasPermission(holder, permission));
}

/**
 * Exact role membership — no implicit admin bypass. The builtin `admin` role
 * holds `*`, so admins already pass every `hasPermission` check; keeping this
 * literal means role checks and permission checks never disagree.
 */
export function hasRole(holder: PermissionHolder, role: string): boolean {
  return holder.roles.includes(role.trim().toLowerCase());
}

export function isSuiteAdmin(holder: PermissionHolder): boolean {
  return holder.permissions.includes(WILDCARD);
}
