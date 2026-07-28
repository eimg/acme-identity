import type Database from "better-sqlite3";
import { hashPassword } from "./passwords.js";

interface SeedRole {
  slug: string;
  name: string;
  description: string;
  permissions: string[];
}

interface SeedUser {
  username: string;
  displayName: string;
  email: string;
  password: string;
  roles: string[];
}

export const BUILTIN_ROLES: SeedRole[] = [
  {
    slug: "admin",
    name: "Admin",
    description: "Full suite access, including identity management",
    permissions: ["*"],
  },
  {
    slug: "operator",
    name: "Operator",
    description: "Run Helix workflows, trigger implementations, merge, manage boards",
    permissions: [
      "identity.read",
      "prelude.write",
      "helix.trigger",
      "helix.merge",
      "issues.write",
      "projects.write",
      "primer.ask",
    ],
  },
  {
    slug: "member",
    name: "Member",
    description: "Create and edit issues, cards, inception docs; query Primer",
    permissions: [
      "identity.read",
      "prelude.write",
      "issues.write",
      "projects.write",
      "primer.ask",
    ],
  },
  {
    slug: "viewer",
    name: "Viewer",
    description: "Read-only access across suite surfaces",
    permissions: [
      "identity.read",
      "prelude.read",
      "helix.read",
      "issues.read",
      "projects.read",
      "primer.ask",
    ],
  },
];

/** Local seed accounts — passwords are intentional for local-first development. */
export const BUILTIN_USERS: SeedUser[] = [
  {
    username: "admin",
    displayName: "Acme Admin",
    email: "admin@acme.local",
    password: "admin",
    roles: ["admin"],
  },
  {
    username: "operator",
    displayName: "Acme Operator",
    email: "operator@acme.local",
    password: "operator",
    roles: ["operator"],
  },
  {
    username: "member",
    displayName: "Acme Member",
    email: "member@acme.local",
    password: "member",
    roles: ["member"],
  },
  {
    username: "viewer",
    displayName: "Acme Viewer",
    email: "viewer@acme.local",
    password: "viewer",
    roles: ["viewer"],
  },
];

export function seedIfEmpty(db: Database.Database): void {
  const roleCount = db.prepare(`SELECT COUNT(*) AS n FROM roles`).get() as { n: number };
  if (roleCount.n > 0) return;

  const now = Date.now();
  const insertRole = db.prepare(`
    INSERT INTO roles (slug, name, description, permissions_json, builtin, created_at, updated_at)
    VALUES (@slug, @name, @description, @permissionsJson, 1, @now, @now)
  `);
  const insertUser = db.prepare(`
    INSERT INTO users (username, display_name, email, password_hash, active, created_at, updated_at)
    VALUES (@username, @displayName, @email, @passwordHash, 1, @now, @now)
  `);
  const insertUserRole = db.prepare(`
    INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)
  `);
  const roleIdBySlug = new Map<string, number>();

  const tx = db.transaction(() => {
    for (const role of BUILTIN_ROLES) {
      const result = insertRole.run({
        slug: role.slug,
        name: role.name,
        description: role.description,
        permissionsJson: JSON.stringify(role.permissions),
        now,
      });
      roleIdBySlug.set(role.slug, Number(result.lastInsertRowid));
    }
    for (const user of BUILTIN_USERS) {
      const result = insertUser.run({
        username: user.username,
        displayName: user.displayName,
        email: user.email,
        passwordHash: hashPassword(user.password),
        now,
      });
      const userId = Number(result.lastInsertRowid);
      for (const slug of user.roles) {
        const roleId = roleIdBySlug.get(slug);
        if (roleId == null) throw new Error(`Unknown seed role ${slug}`);
        insertUserRole.run(userId, roleId);
      }
    }
  });
  tx();
}
