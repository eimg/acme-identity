import type Database from "better-sqlite3";
import { hashPassword, verifyPassword } from "./passwords.js";
import type { PermissionInfo } from "./types.js";

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

/**
 * Builtin roles whose permissions cannot be edited. Editing `admin` away from
 * `*` would leave nobody able to manage identity, so it stays pinned.
 */
export const PERMISSION_LOCKED_ROLES = new Set(["admin"]);

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
    description: "Run workflows and operate suite observability",
    permissions: [
      "identity.read",
      "prelude.write",
      "prelude.export",
      "helix.read",
      "helix.trigger",
      "helix.review",
      "helix.merge",
      "helix.bootstrap",
      "issues.write",
      "projects.write",
      "primer.ask",
      "primer.manage",
      "observability.read",
      "observability.collect",
      "observability.manage",
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
      "observability.read",
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
      "observability.read",
    ],
  },
];

/**
 * Suite gate vocabulary, served from `/api/meta` so the manage UI and suite
 * consumers pick permissions from one list instead of retyping strings. Products
 * may still gate on keys that are not listed here.
 */
export const PERMISSION_VOCABULARY: PermissionInfo[] = [
  { key: "*", product: "suite", description: "Everything (builtin admin role)" },
  { key: "identity.read", product: "identity", description: "List users and roles" },
  {
    key: "identity.admin",
    product: "identity",
    description: "Manage users, roles, and service tokens",
  },
  { key: "prelude.read", product: "prelude", description: "View inceptions" },
  {
    key: "prelude.write",
    product: "prelude",
    description: "Edit inceptions, documents, discussions",
  },
  { key: "prelude.export", product: "prelude", description: "Export bootstrap artifacts" },
  { key: "prelude.discuss", product: "prelude", description: "Participate in discussions" },
  {
    key: "prelude.context",
    product: "prelude",
    description: "Mark discussion topics include-in-context",
  },
  { key: "helix.read", product: "helix", description: "View workflows and runs" },
  { key: "helix.trigger", product: "helix", description: "Trigger runs" },
  { key: "helix.review", product: "helix", description: "Run independent PR reviews" },
  { key: "helix.merge", product: "helix", description: "Merge implementation output" },
  { key: "helix.bootstrap", product: "helix", description: "Bootstrap a target repository" },
  { key: "helix.manage", product: "helix", description: "Author Helix agents, skills, and workflows" },
  { key: "helix.admin", product: "helix", description: "Administer Helix run history" },
  { key: "steering.read", product: "steering", description: "View Steering cases and workflow activity" },
  { key: "steering.decide", product: "steering", description: "Resolve Steering cases" },
  { key: "steering.notify.prelude", product: "steering", description: "Publish Prelude workflow events" },
  { key: "steering.notify.helix", product: "steering", description: "Publish Helix workflow events" },
  { key: "steering.notify.issues", product: "steering", description: "Publish Acme Issues workflow events" },
  { key: "steering.notify.projects", product: "steering", description: "Publish Acme Projects workflow events" },
  { key: "prelude.steering.export", product: "prelude", description: "Apply a Steering-authorized Prelude export" },
  { key: "prelude.steering.receive", product: "prelude", description: "Record a Steering decision for Prelude" },
  { key: "helix.steering.recover", product: "helix", description: "Apply a Steering-authorized run recovery" },
  { key: "helix.steering.receive", product: "helix", description: "Record a Steering decision for Helix" },
  { key: "issues.steering.trigger", product: "issues", description: "Apply a Steering-authorized implementation trigger" },
  { key: "issues.steering.receive", product: "issues", description: "Record a Steering decision for Issues" },
  { key: "projects.steering.submit", product: "projects", description: "Apply a Steering-authorized issue submission" },
  { key: "projects.steering.receive", product: "projects", description: "Record a Steering decision for Projects" },
  { key: "issues.read", product: "issues", description: "View issues and local PRs" },
  { key: "issues.write", product: "issues", description: "Create and edit issues and PRs" },
  { key: "projects.read", product: "projects", description: "View the feature board" },
  { key: "projects.write", product: "projects", description: "Edit the feature board" },
  {
    key: "primer.ask",
    product: "primer",
    description: "Grounded chat (evidence ACL still enforced in Primer)",
  },
  {
    key: "primer.manage",
    product: "primer",
    description: "Manage Primer actors, sources, synchronization, and evaluation",
  },
  {
    key: "observability.read",
    product: "observability",
    description: "View suite observations, traces, and source health",
  },
  {
    key: "observability.collect",
    product: "observability",
    description: "Run read-only source collection",
  },
  {
    key: "observability.manage",
    product: "observability",
    description: "Manage observability configuration and rebuild derived data",
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
  { username: "maya.chen", displayName: "Maya Chen", email: "maya.chen@acme.test", password: "maya.chen", roles: ["member"] },
  { username: "owen.park", displayName: "Owen Park", email: "owen.park@acme.test", password: "owen.park", roles: ["member"] },
  { username: "priya.nair", displayName: "Priya Nair", email: "priya.nair@acme.test", password: "priya.nair", roles: ["operator"] },
  { username: "lena.morales", displayName: "Lena Morales", email: "lena.morales@acme.test", password: "lena.morales", roles: ["member"] },
  { username: "ana.silva", displayName: "Ana Silva", email: "ana.silva@acme.test", password: "ana.silva", roles: ["operator"] },
  { username: "marcus.bell", displayName: "Marcus Bell", email: "marcus.bell@acme.test", password: "marcus.bell", roles: ["member"] },
  { username: "eli.turner", displayName: "Eli Turner", email: "eli.turner@acme.test", password: "eli.turner", roles: ["member"] },
  { username: "noah.price", displayName: "Noah Price", email: "noah.price@acme.test", password: "noah.price", roles: ["viewer"] },
  { username: "samira.khan", displayName: "Samira Khan", email: "samira.khan@acme.test", password: "samira.khan", roles: ["member"] },
];

export function seedIfEmpty(db: Database.Database): void {
  const roleCount = db.prepare(`SELECT COUNT(*) AS n FROM roles`).get() as { n: number };
  if (roleCount.n > 0) {
    seedMissingPrimerActors(db);
    return;
  }

  const adminPassword = process.env.ACME_IDENTITY_ADMIN_PASSWORD?.trim();
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
      const password =
        user.username === "admin" && adminPassword ? adminPassword : user.password;
      const result = insertUser.run({
        username: user.username,
        displayName: user.displayName,
        email: user.email,
        passwordHash: hashPassword(password),
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

/** Add fixture-compatible human logins to existing local Identity databases without changing existing users or roles. */
function seedMissingPrimerActors(db: Database.Database): void {
  const operator = db.prepare("SELECT permissions_json FROM roles WHERE slug = 'operator'")
    .get() as { permissions_json: string } | undefined;
  if (operator) {
    const permissions = JSON.parse(operator.permissions_json) as string[];
    if (!permissions.includes("primer.manage")) {
      db.prepare("UPDATE roles SET permissions_json = ?, updated_at = ? WHERE slug = 'operator'")
        .run(JSON.stringify([...permissions, "primer.manage"]), Date.now());
    }
  }
  const insertUser = db.prepare(`
    INSERT INTO users (username, display_name, email, password_hash, active, created_at, updated_at)
    VALUES (@username, @displayName, @email, @passwordHash, 1, @now, @now)
  `);
  const insertUserRole = db.prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)");
  const getRole = db.prepare("SELECT id FROM roles WHERE slug = ?") as Database.Statement<[string], { id: number }>;
  const exists = db.prepare("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE");
  const fixtureUsers = BUILTIN_USERS.filter((user) => user.email.endsWith("@acme.test"));
  db.transaction(() => {
    for (const user of fixtureUsers) {
      if (exists.get(user.username)) continue;
      const now = Date.now();
      const result = insertUser.run({
        username: user.username,
        displayName: user.displayName,
        email: user.email,
        passwordHash: hashPassword(user.password),
        now,
      });
      for (const slug of user.roles) {
        const role = getRole.get(slug);
        if (!role) throw new Error(`Unknown seed role ${slug}`);
        insertUserRole.run(Number(result.lastInsertRowid), role.id);
      }
    }
  })();
}

/** True while the admin account still has its well-known development password. */
export function usingSeedAdminPassword(db: Database.Database): boolean {
  const row = db
    .prepare(`SELECT password_hash AS hash FROM users WHERE username = 'admin' COLLATE NOCASE`)
    .get() as { hash: string } | undefined;
  return row ? verifyPassword("admin", row.hash) : false;
}
