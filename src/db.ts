import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { seedIfEmpty } from "./seed.js";

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

export function resolveDataDir(): string {
  return process.env.ACME_IDENTITY_DATA_DIR ?? join(projectRoot, "data");
}

export function openDatabase(dataDir = resolveDataDir()): Database.Database {
  mkdirSync(dataDir, { recursive: true });
  const db = new Database(join(dataDir, "identity.db"));
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  // A second process (CLI recovery command while the server runs) should wait, not fail.
  db.pragma("busy_timeout = 5000");
  migrate(db);
  seedIfEmpty(db);
  deleteExpiredSessions(db);
  return db;
}

export function deleteExpiredSessions(db: Database.Database): number {
  return db.prepare(`DELETE FROM sessions WHERE expires_at < ?`).run(Date.now()).changes;
}

type Migration = {
  version: number;
  up: (db: Database.Database) => void;
};

/**
 * Append-only list keyed to `PRAGMA user_version`. Never edit a shipped step:
 * add a new one, so existing `data/identity.db` files upgrade in place.
 */
const MIGRATIONS: Migration[] = [
  {
    version: 1,
    up: (db) =>
      db.exec(`
        CREATE TABLE IF NOT EXISTS roles (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          slug TEXT NOT NULL UNIQUE,
          name TEXT NOT NULL,
          description TEXT NOT NULL DEFAULT '',
          permissions_json TEXT NOT NULL DEFAULT '[]',
          builtin INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          display_name TEXT NOT NULL,
          email TEXT NOT NULL DEFAULT '',
          password_hash TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_roles (
          user_id INTEGER NOT NULL,
          role_id INTEGER NOT NULL,
          PRIMARY KEY (user_id, role_id),
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sessions (
          id TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

        CREATE TABLE IF NOT EXISTS service_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          token_hash TEXT NOT NULL UNIQUE,
          token_prefix TEXT NOT NULL,
          role_slugs_json TEXT NOT NULL DEFAULT '[]',
          created_at INTEGER NOT NULL,
          last_used_at INTEGER
        );
      `),
  },
  {
    version: 2,
    up: (db) => {
      if (!hasColumn(db, "service_tokens", "expires_at")) {
        db.exec(`ALTER TABLE service_tokens ADD COLUMN expires_at INTEGER`);
      }
    },
  },
];

function migrate(db: Database.Database): void {
  const current = Number((db.pragma("user_version", { simple: true }) as number) ?? 0);
  for (const migration of MIGRATIONS) {
    if (migration.version <= current) continue;
    db.transaction(() => {
      migration.up(db);
    })();
    db.pragma(`user_version = ${migration.version}`);
  }
}

function hasColumn(db: Database.Database, table: string, column: string): boolean {
  const rows = db.pragma(`table_info(${table})`) as Array<{ name: string }>;
  return rows.some((row) => row.name === column);
}
