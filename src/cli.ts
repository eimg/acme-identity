#!/usr/bin/env node
import { openDatabase } from "./db.js";
import { startServer } from "./app.js";
import { resolveAuthMode } from "./mode.js";
import { DEFAULT_PORT } from "./types.js";

function usage(): never {
  console.error(`Usage:
  acme-identity serve [--port <n>] [--host <host>] [--mode off|local]

Environment:
  ACME_IDENTITY_DATA_DIR  Directory for SQLite database (default: ./data)
  ACME_AUTH_MODE          off | local (default: local for this server)
  ACME_ALLOW_INSECURE     Set to 1 to allow mode=off outside test/dev
  PORT                    Default port if --port is not given`);
  process.exit(2);
}

function parseArgs(args: string[]): { port: number; host: string; mode?: string } {
  let port = Number(process.env.PORT ?? DEFAULT_PORT);
  let host = "127.0.0.1";
  let mode: string | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--port") {
      port = Number(args[++i]);
      if (!Number.isInteger(port) || port <= 0) usage();
    } else if (args[i] === "--host") {
      host = args[++i];
    } else if (args[i] === "--mode") {
      mode = args[++i];
    } else {
      usage();
    }
  }
  return { port, host, mode };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args[0] !== "serve") usage();
  const { port, host, mode } = parseArgs(args.slice(1));
  if (mode) process.env.ACME_AUTH_MODE = mode;
  const authMode = resolveAuthMode();
  const db = openDatabase();
  const server = startServer({ db, port, host, authMode });
  await new Promise<void>((resolve, reject) => {
    const stop = () => server.close((error) => (error ? reject(error) : resolve()));
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  db.close();
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
