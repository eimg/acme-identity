import type Database from "better-sqlite3";
import { deleteExpiredSessions } from "./db.js";
import {
  DUMMY_PASSWORD_HASH,
  hashPassword,
  hashToken,
  isLegacyTokenHash,
  newServiceToken,
  newSessionId,
  tokenPrefix,
  verifyPassword,
  verifyToken,
} from "./passwords.js";
import { grants, isValidPermission, normalizePermission } from "./permissions.js";
import { PERMISSION_LOCKED_ROLES } from "./seed.js";
import type { Role, ServiceToken, SessionInfo, User } from "./types.js";

const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 14;
/** Skip the `last_used_at` write when it would barely move, so token auth stays read-only. */
const TOKEN_USE_WRITE_INTERVAL_MS = 60_000;
/** Permission that must remain reachable by at least one active user. */
const ADMIN_PERMISSION = "identity.admin";

type RoleRow = {
  id: number;
  slug: string;
  name: string;
  description: string;
  permissions_json: string;
  builtin: number;
  created_at: number;
  updated_at: number;
};

type UserRow = {
  id: number;
  username: string;
  display_name: string;
  email: string;
  active: number;
  created_at: number;
  updated_at: number;
};

type ServiceTokenRow = {
  id: number;
  name: string;
  token_hash: string;
  token_prefix: string;
  role_slugs_json: string;
  created_at: number;
  last_used_at: number | null;
  expires_at: number | null;
};

/** Caller-fixable validation failure; surfaced as HTTP 400. */
export class StoreError extends Error {
  readonly status = 400;
}

function mapRole(row: RoleRow): Role {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    description: row.description,
    permissions: JSON.parse(row.permissions_json) as string[],
    builtin: row.builtin === 1,
    permissionsLocked: PERMISSION_LOCKED_ROLES.has(row.slug),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapUser(row: UserRow, roleSlugs: string[]): User {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    email: row.email,
    active: row.active === 1,
    roleSlugs,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapServiceToken(row: ServiceTokenRow): ServiceToken {
  return {
    id: row.id,
    name: row.name,
    tokenPrefix: row.token_prefix,
    roleSlugs: JSON.parse(row.role_slugs_json) as string[],
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    expiresAt: row.expires_at,
  };
}

function roleSlugsForUser(db: Database.Database, userId: number): string[] {
  const rows = db
    .prepare(
      `SELECT r.slug AS slug
       FROM user_roles ur
       JOIN roles r ON r.id = ur.role_id
       WHERE ur.user_id = ?
       ORDER BY r.slug`,
    )
    .all(userId) as Array<{ slug: string }>;
  return rows.map((row) => row.slug);
}

export function listRoles(db: Database.Database): Role[] {
  const rows = db
    .prepare(`SELECT * FROM roles ORDER BY builtin DESC, slug ASC`)
    .all() as RoleRow[];
  return rows.map(mapRole);
}

export function getRoleBySlug(db: Database.Database, slug: string): Role | undefined {
  const row = db.prepare(`SELECT * FROM roles WHERE slug = ?`).get(slug) as RoleRow | undefined;
  return row ? mapRole(row) : undefined;
}

export function getRoleById(db: Database.Database, id: number): Role | undefined {
  if (!Number.isInteger(id)) return undefined;
  const row = db.prepare(`SELECT * FROM roles WHERE id = ?`).get(id) as RoleRow | undefined;
  return row ? mapRole(row) : undefined;
}

export function createRole(
  db: Database.Database,
  input: { slug: string; name: string; description?: string; permissions?: string[] },
): Role {
  const slug = normalizeSlug(input.slug);
  if (!slug) throw new StoreError("slug is required");
  if (!input.name.trim()) throw new StoreError("name is required");
  if (getRoleBySlug(db, slug)) throw new StoreError("Role slug already exists");
  const permissions = validatePermissions(input.permissions ?? []);
  const now = Date.now();
  const result = db
    .prepare(
      `INSERT INTO roles (slug, name, description, permissions_json, builtin, created_at, updated_at)
       VALUES (?, ?, ?, ?, 0, ?, ?)`,
    )
    .run(
      slug,
      input.name.trim(),
      input.description?.trim() ?? "",
      JSON.stringify(permissions),
      now,
      now,
    );
  return getRoleById(db, Number(result.lastInsertRowid))!;
}

export function updateRole(
  db: Database.Database,
  id: number,
  patch: { name?: string; description?: string; permissions?: string[] },
): Role | undefined {
  const existing = getRoleById(db, id);
  if (!existing) return undefined;
  if (patch.permissions !== undefined && existing.permissionsLocked) {
    const next = validatePermissions(patch.permissions);
    if (!sameMembers(next, existing.permissions)) {
      throw new StoreError(`Permissions of the builtin ${existing.slug} role are fixed`);
    }
  }
  const permissions =
    patch.permissions !== undefined && !existing.permissionsLocked
      ? validatePermissions(patch.permissions)
      : existing.permissions;
  const now = Date.now();
  db.transaction(() => {
    db.prepare(
      `UPDATE roles
       SET name = ?, description = ?, permissions_json = ?, updated_at = ?
       WHERE id = ?`,
    ).run(
      patch.name?.trim() || existing.name,
      patch.description !== undefined ? patch.description.trim() : existing.description,
      JSON.stringify(permissions),
      now,
      id,
    );
    assertIdentityAdminRemains(db);
  })();
  return getRoleById(db, id);
}

export function deleteRole(db: Database.Database, id: number): boolean {
  const existing = getRoleById(db, id);
  if (!existing) return false;
  if (existing.builtin) throw new StoreError("Builtin roles cannot be deleted");
  const inUse = db
    .prepare(`SELECT COUNT(*) AS n FROM user_roles WHERE role_id = ?`)
    .get(id) as { n: number };
  if (inUse.n > 0) throw new StoreError("Role is assigned to one or more users");
  const tokenUse = listServiceTokens(db).filter((token) => token.roleSlugs.includes(existing.slug));
  if (tokenUse.length > 0) throw new StoreError("Role is assigned to one or more service tokens");
  db.prepare(`DELETE FROM roles WHERE id = ?`).run(id);
  return true;
}

export function listUsers(db: Database.Database): User[] {
  const rows = db
    .prepare(`SELECT id, username, display_name, email, active, created_at, updated_at FROM users ORDER BY username`)
    .all() as UserRow[];
  return rows.map((row) => mapUser(row, roleSlugsForUser(db, row.id)));
}

export function getUserById(db: Database.Database, id: number): User | undefined {
  if (!Number.isInteger(id)) return undefined;
  const row = db
    .prepare(
      `SELECT id, username, display_name, email, active, created_at, updated_at FROM users WHERE id = ?`,
    )
    .get(id) as UserRow | undefined;
  return row ? mapUser(row, roleSlugsForUser(db, row.id)) : undefined;
}

export function getUserByUsername(db: Database.Database, username: string): User | undefined {
  const row = db
    .prepare(
      `SELECT id, username, display_name, email, active, created_at, updated_at
       FROM users WHERE username = ? COLLATE NOCASE`,
    )
    .get(username.trim()) as UserRow | undefined;
  return row ? mapUser(row, roleSlugsForUser(db, row.id)) : undefined;
}

function getPasswordHash(db: Database.Database, userId: number): string | undefined {
  const row = db.prepare(`SELECT password_hash FROM users WHERE id = ?`).get(userId) as
    | { password_hash: string }
    | undefined;
  return row?.password_hash;
}

export function createUser(
  db: Database.Database,
  input: {
    username: string;
    displayName: string;
    email?: string;
    password: string;
    roleSlugs: string[];
    active?: boolean;
  },
): User {
  const username = normalizeUsername(input.username);
  if (!username) throw new StoreError("username is required");
  if (!input.displayName.trim()) throw new StoreError("displayName is required");
  if (!input.password) throw new StoreError("password is required");
  if (getUserByUsername(db, username)) throw new StoreError("Username already exists");
  const roleIds = resolveRoleIds(db, input.roleSlugs);
  const now = Date.now();
  const tx = db.transaction(() => {
    const result = db
      .prepare(
        `INSERT INTO users (username, display_name, email, password_hash, active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        username,
        input.displayName.trim(),
        input.email?.trim() ?? "",
        hashPassword(input.password),
        input.active === false ? 0 : 1,
        now,
        now,
      );
    const userId = Number(result.lastInsertRowid);
    const insert = db.prepare(`INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`);
    for (const roleId of roleIds) insert.run(userId, roleId);
    return userId;
  });
  return getUserById(db, tx())!;
}

export function updateUser(
  db: Database.Database,
  id: number,
  patch: {
    displayName?: string;
    email?: string;
    password?: string;
    roleSlugs?: string[];
    active?: boolean;
  },
): User | undefined {
  const existing = getUserById(db, id);
  if (!existing) return undefined;
  const now = Date.now();
  const tx = db.transaction(() => {
    db.prepare(
      `UPDATE users
       SET display_name = ?, email = ?, active = ?, updated_at = ?
       WHERE id = ?`,
    ).run(
      patch.displayName?.trim() || existing.displayName,
      patch.email !== undefined ? patch.email.trim() : existing.email,
      patch.active === undefined ? (existing.active ? 1 : 0) : patch.active ? 1 : 0,
      now,
      id,
    );
    if (patch.password) {
      db.prepare(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`).run(
        hashPassword(patch.password),
        now,
        id,
      );
    }
    if (patch.roleSlugs) {
      const roleIds = resolveRoleIds(db, patch.roleSlugs);
      db.prepare(`DELETE FROM user_roles WHERE user_id = ?`).run(id);
      const insert = db.prepare(`INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`);
      for (const roleId of roleIds) insert.run(id, roleId);
    }
    // A password change or a deactivation must not leave live sessions behind.
    if (patch.password || patch.active === false) deleteSessionsForUser(db, id);
    assertIdentityAdminRemains(db);
  });
  tx();
  return getUserById(db, id);
}

export function deleteUser(db: Database.Database, id: number): boolean {
  const existing = getUserById(db, id);
  if (!existing) return false;
  db.transaction(() => {
    db.prepare(`DELETE FROM users WHERE id = ?`).run(id);
    assertIdentityAdminRemains(db);
  })();
  return true;
}

export function authenticateUser(
  db: Database.Database,
  username: string,
  password: string,
): User | undefined {
  const user = getUserByUsername(db, username);
  const stored = user ? getPasswordHash(db, user.id) : undefined;
  // Always spend one KDF pass so unknown/inactive users are not distinguishable by timing.
  const ok = verifyPassword(password, stored ?? DUMMY_PASSWORD_HASH);
  if (!user || !user.active || !stored || !ok) return undefined;
  return user;
}

export function createSession(db: Database.Database, userId: number): SessionInfo {
  const id = newSessionId();
  const createdAt = Date.now();
  const expiresAt = createdAt + SESSION_TTL_MS;
  db.transaction(() => {
    deleteExpiredSessions(db);
    db.prepare(
      `INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
    ).run(id, userId, createdAt, expiresAt);
  })();
  return { id, userId, createdAt, expiresAt };
}

export function getSession(db: Database.Database, sessionId: string): SessionInfo | undefined {
  const row = db
    .prepare(`SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = ?`)
    .get(sessionId) as
    | { id: string; user_id: number; created_at: number; expires_at: number }
    | undefined;
  if (!row) return undefined;
  if (row.expires_at < Date.now()) {
    db.prepare(`DELETE FROM sessions WHERE id = ?`).run(sessionId);
    return undefined;
  }
  return {
    id: row.id,
    userId: row.user_id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  };
}

export function deleteSession(db: Database.Database, sessionId: string): void {
  db.prepare(`DELETE FROM sessions WHERE id = ?`).run(sessionId);
}

export function deleteSessionsForUser(
  db: Database.Database,
  userId: number,
  keepSessionId?: string,
): number {
  const result = keepSessionId
    ? db.prepare(`DELETE FROM sessions WHERE user_id = ? AND id <> ?`).run(userId, keepSessionId)
    : db.prepare(`DELETE FROM sessions WHERE user_id = ?`).run(userId);
  return result.changes;
}

export function countSessionsForUser(db: Database.Database, userId: number): number {
  const row = db
    .prepare(`SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND expires_at >= ?`)
    .get(userId, Date.now()) as { n: number };
  return row.n;
}

export function permissionsForRoles(db: Database.Database, roleSlugs: string[]): string[] {
  if (roleSlugs.length === 0) return [];
  const placeholders = roleSlugs.map(() => "?").join(", ");
  const rows = db
    .prepare(`SELECT permissions_json FROM roles WHERE slug IN (${placeholders})`)
    .all(...roleSlugs) as Array<{ permissions_json: string }>;
  const set = new Set<string>();
  for (const row of rows) {
    for (const permission of JSON.parse(row.permissions_json) as string[]) {
      set.add(permission);
    }
  }
  return [...set].sort();
}

export function listServiceTokens(db: Database.Database): ServiceToken[] {
  const rows = db
    .prepare(
      `SELECT id, name, token_hash, token_prefix, role_slugs_json, created_at, last_used_at, expires_at
       FROM service_tokens ORDER BY created_at DESC`,
    )
    .all() as ServiceTokenRow[];
  return rows.map(mapServiceToken);
}

export function createServiceTokenRecord(
  db: Database.Database,
  input: { name: string; roleSlugs: string[]; expiresAt?: number | null },
): ServiceToken {
  const name = input.name.trim();
  if (!name) throw new StoreError("name is required");
  resolveRoleIds(db, input.roleSlugs);
  if (input.expiresAt != null && input.expiresAt <= Date.now()) {
    throw new StoreError("expiresAt must be in the future");
  }
  const token = newServiceToken();
  const now = Date.now();
  const result = db
    .prepare(
      `INSERT INTO service_tokens (name, token_hash, token_prefix, role_slugs_json, created_at, last_used_at, expires_at)
       VALUES (?, ?, ?, ?, ?, NULL, ?)`,
    )
    .run(
      name,
      hashToken(token),
      tokenPrefix(token),
      JSON.stringify(input.roleSlugs),
      now,
      input.expiresAt ?? null,
    );
  return {
    id: Number(result.lastInsertRowid),
    name,
    tokenPrefix: tokenPrefix(token),
    roleSlugs: input.roleSlugs,
    createdAt: now,
    lastUsedAt: null,
    expiresAt: input.expiresAt ?? null,
    token,
  };
}

export function deleteServiceToken(db: Database.Database, id: number): boolean {
  if (!Number.isInteger(id)) return false;
  const result = db.prepare(`DELETE FROM service_tokens WHERE id = ?`).run(id);
  return result.changes > 0;
}

/**
 * Resolves a presented token in one indexed lookup. The stored digest is
 * deterministic, so cost does not grow with the number of minted tokens — which
 * also means an invalid token is rejected without any KDF work.
 */
export function findServiceToken(
  db: Database.Database,
  rawToken: string,
): { id: number; roleSlugs: string[]; name: string } | undefined {
  const row =
    (db
      .prepare(
        `SELECT id, name, token_hash, token_prefix, role_slugs_json, created_at, last_used_at, expires_at
         FROM service_tokens WHERE token_hash = ?`,
      )
      .get(hashToken(rawToken)) as ServiceTokenRow | undefined) ??
    findLegacyServiceToken(db, rawToken);
  if (!row) return undefined;
  if (row.expires_at != null && row.expires_at < Date.now()) return undefined;

  const now = Date.now();
  if (row.last_used_at == null || now - row.last_used_at > TOKEN_USE_WRITE_INTERVAL_MS) {
    db.prepare(`UPDATE service_tokens SET last_used_at = ? WHERE id = ?`).run(now, row.id);
  }
  return {
    id: row.id,
    name: row.name,
    roleSlugs: JSON.parse(row.role_slugs_json) as string[],
  };
}

/**
 * Tokens minted before digests became deterministic are salted, so they can only
 * be found by scanning. New installs never hit this; existing ones keep working
 * until those tokens are rotated.
 */
function findLegacyServiceToken(
  db: Database.Database,
  rawToken: string,
): ServiceTokenRow | undefined {
  const rows = db
    .prepare(
      `SELECT id, name, token_hash, token_prefix, role_slugs_json, created_at, last_used_at, expires_at
       FROM service_tokens WHERE token_hash LIKE 'scrypt$%'`,
    )
    .all() as ServiceTokenRow[];
  return rows.find(
    (row) => isLegacyTokenHash(row.token_hash) && verifyToken(rawToken, row.token_hash),
  );
}

/** Users who can still administer identity, so no edit can lock everyone out. */
export function countIdentityAdmins(db: Database.Database): number {
  const rows = db
    .prepare(
      `SELECT u.id AS id, r.permissions_json AS permissions_json
       FROM users u
       JOIN user_roles ur ON ur.user_id = u.id
       JOIN roles r ON r.id = ur.role_id
       WHERE u.active = 1`,
    )
    .all() as Array<{ id: number; permissions_json: string }>;
  const admins = new Set<number>();
  for (const row of rows) {
    const permissions = JSON.parse(row.permissions_json) as string[];
    if (permissions.some((permission) => grants(permission, ADMIN_PERMISSION))) admins.add(row.id);
  }
  return admins.size;
}

function assertIdentityAdminRemains(db: Database.Database): void {
  if (countIdentityAdmins(db) === 0) {
    throw new StoreError(
      `At least one active user must keep a role granting ${ADMIN_PERMISSION}`,
    );
  }
}

function resolveRoleIds(db: Database.Database, slugs: string[]): number[] {
  if (!slugs.length) throw new StoreError("At least one role is required");
  const ids: number[] = [];
  for (const slug of slugs) {
    const role = getRoleBySlug(db, slug);
    if (!role) throw new StoreError(`Unknown role: ${slug}`);
    ids.push(role.id);
  }
  return ids;
}

function validatePermissions(permissions: string[]): string[] {
  const normalized = permissions.map(normalizePermission).filter(Boolean);
  for (const permission of normalized) {
    if (!isValidPermission(permission)) {
      throw new StoreError(
        `Invalid permission "${permission}" — use "*", "product.*", or "product.action"`,
      );
    }
  }
  return [...new Set(normalized)].sort();
}

function sameMembers(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const set = new Set(b);
  return a.every((item) => set.has(item));
}

function normalizeUsername(value: string): string {
  const username = value.trim();
  if (/\s/.test(username)) throw new StoreError("username cannot contain whitespace");
  return username;
}

function normalizeSlug(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
