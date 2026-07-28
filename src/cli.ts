#!/usr/bin/env node
import { createInterface } from "node:readline/promises";
import { startServer } from "./app.js";
import { openDatabase } from "./db.js";
import { resolveAuthMode } from "./mode.js";
import {
  createServiceTokenRecord,
  getUserByUsername,
  listServiceTokens,
  listUsers,
  updateUser,
} from "./store.js";
import { DEFAULT_PORT } from "./types.js";

function usage(): never {
  console.error(`Usage:
  acme-identity serve [--port <n>] [--host <host>] [--mode off|local]
  acme-identity list-users
  acme-identity set-password <username>        # reads the password from stdin
  acme-identity mint-token <name> <role>[,<role>…] [--expires-in-days <n>]
  acme-identity list-tokens

Environment:
  ACME_IDENTITY_DATA_DIR        Directory for SQLite database (default: ./data)
  ACME_AUTH_MODE                off | local (default: local for this server)
  ACME_ALLOW_INSECURE           Set to 1 to allow mode=off outside test/dev
  ACME_DEV_PRINCIPAL            Off mode: seeded user anonymous callers resolve as
  ACME_IDENTITY_ADMIN_PASSWORD  Admin password used when first seeding
  ACME_IDENTITY_ALLOWED_ORIGINS Comma-separated origins allowed to call the API from a browser
  ACME_IDENTITY_COOKIE_SECURE   1 | 0 to force the session cookie Secure flag
  ACME_IDENTITY_TRUST_PROXY     Set to 1 when running behind a reverse proxy
  PORT                          Default port if --port is not given`);
  process.exit(2);
}

function parseServeArgs(args: string[]): { port: number; host: string; mode?: string } {
  let port = Number(process.env.PORT ?? DEFAULT_PORT);
  let host = "127.0.0.1";
  let mode: string | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--port") {
      port = Number(args[++i]);
      if (!Number.isInteger(port) || port <= 0) usage();
    } else if (args[i] === "--host") {
      host = args[++i] ?? usage();
    } else if (args[i] === "--mode") {
      mode = args[++i] ?? usage();
    } else {
      usage();
    }
  }
  return { port, host, mode };
}

async function serve(args: string[]): Promise<void> {
  const { port, host, mode } = parseServeArgs(args);
  if (mode) process.env.ACME_AUTH_MODE = mode;
  const authMode = resolveAuthMode();
  const db = openDatabase();
  const server = startServer({ db, port, host, authMode });
  await new Promise<void>((resolve, reject) => {
    const stop = () => {
      server.close((error) => (error ? reject(error) : resolve()));
      // Keep-alive sockets would otherwise hold the process open past close().
      server.closeAllConnections?.();
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  db.close();
}

/** Recovery path: an operator who is locked out can always reset a password locally. */
async function setPassword(username: string | undefined): Promise<void> {
  if (!username) usage();
  const db = openDatabase();
  try {
    const user = getUserByUsername(db, username);
    if (!user) {
      console.error(`No such user: ${username}`);
      process.exitCode = 1;
      return;
    }
    const password = (await readSecret("New password: ")).trim();
    if (!password) {
      console.error("Password cannot be empty");
      process.exitCode = 1;
      return;
    }
    updateUser(db, user.id, { password });
    console.log(`Password updated for ${user.username}; existing sessions were revoked.`);
  } finally {
    db.close();
  }
}

function listUsersCommand(): void {
  const db = openDatabase();
  try {
    for (const user of listUsers(db)) {
      console.log(
        `${user.id}\t${user.username}\t${user.active ? "active" : "disabled"}\t${user.roleSlugs.join(",")}`,
      );
    }
  } finally {
    db.close();
  }
}

function mintToken(args: string[]): void {
  const [name, roles, ...rest] = args;
  if (!name || !roles) usage();
  let expiresAt: number | null = null;
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "--expires-in-days") {
      const days = Number(rest[++i]);
      if (!Number.isFinite(days) || days <= 0) usage();
      expiresAt = Date.now() + days * 86_400_000;
    } else {
      usage();
    }
  }
  const db = openDatabase();
  try {
    const token = createServiceTokenRecord(db, {
      name,
      roleSlugs: roles.split(",").map((slug) => slug.trim()).filter(Boolean),
      expiresAt,
    });
    console.log(token.token);
  } finally {
    db.close();
  }
}

function listTokensCommand(): void {
  const db = openDatabase();
  try {
    for (const token of listServiceTokens(db)) {
      const expiry = token.expiresAt ? new Date(token.expiresAt).toISOString() : "never";
      console.log(`${token.id}\t${token.name}\t${token.tokenPrefix}…\t${token.roleSlugs.join(",")}\texpires:${expiry}`);
    }
  } finally {
    db.close();
  }
}

async function readSecret(prompt: string): Promise<string> {
  if (process.env.ACME_IDENTITY_NEW_PASSWORD) return process.env.ACME_IDENTITY_NEW_PASSWORD;
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: false });
  try {
    process.stderr.write(prompt);
    const answer = await rl[Symbol.asyncIterator]().next();
    return answer.done ? "" : answer.value;
  } finally {
    rl.close();
  }
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  switch (command) {
    case "serve":
      return serve(args);
    case "list-users":
      return listUsersCommand();
    case "set-password":
      return setPassword(args[0]);
    case "mint-token":
      return mintToken(args);
    case "list-tokens":
      return listTokensCommand();
    default:
      usage();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
