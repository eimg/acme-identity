import express, { type Express, type NextFunction, type Request, type Response } from "express";
import type { Server } from "node:http";
import type Database from "better-sqlite3";
import { assertInsecureModeAllowed, resolveAuthMode } from "./mode.js";
import {
  devAdminPrincipal,
  hasPermission,
  principalFromService,
  principalFromUser,
} from "./principal.js";
import {
  authenticateUser,
  createRole,
  createServiceTokenRecord,
  createSession,
  createUser,
  deleteRole,
  deleteServiceToken,
  deleteSession,
  deleteUser,
  findServiceToken,
  getSession,
  getUserById,
  listRoles,
  listServiceTokens,
  listUsers,
  updateRole,
  updateUser,
} from "./store.js";
import type { AuthMode, Principal } from "./types.js";
import { ISSUER, SESSION_COOKIE } from "./types.js";
import { attachHmr, webAssets, webFromSource, webIndex } from "./webAssets.js";

type Locals = {
  principal?: Principal;
};

export function createApp({
  db,
  authMode = resolveAuthMode(),
}: {
  db: Database.Database;
  authMode?: AuthMode;
}): Express {
  assertInsecureModeAllowed(authMode);
  const app = express();
  app.use(express.json());
  app.use(webAssets());

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true, issuer: ISSUER, authMode });
  });

  app.get("/api/meta", (_req, res) => {
    res.json({
      schemaVersion: "acme.identity.meta.v1",
      issuer: ISSUER,
      authMode,
      defaultDevPrincipal: "admin",
      roles: listRoles(db).map((role) => ({
        slug: role.slug,
        name: role.name,
        builtin: role.builtin,
      })),
    });
  });

  app.post("/api/session", (req, res) => {
    const body = req.body as Record<string, unknown>;
    const username = text(body.username);
    const password = typeof body.password === "string" ? body.password : "";
    if (!username || !password) {
      return res.status(400).json({ error: "username and password are required" });
    }
    const user = authenticateUser(db, username, password);
    if (!user) return res.status(401).json({ error: "Invalid username or password" });
    const session = createSession(db, user.id);
    const principal = principalFromUser(db, user, authMode);
    res
      .set("set-cookie", sessionCookie(session.id, session.expiresAt))
      .status(201)
      .json({
        schemaVersion: "acme.session.v1",
        session: {
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
        },
        principal,
        user,
      });
  });

  app.get("/api/session", (req, res) => {
    const principal = resolveRequestPrincipal(db, req, authMode, { allowAnonymousOff: true });
    if (!principal) return res.status(401).json({ error: "Not signed in" });
    const user =
      principal.kind === "user"
        ? getUserById(db, Number(principal.sub.replace(/^user:/, "")))
        : undefined;
    res.json({
      schemaVersion: "acme.session.v1",
      principal,
      user: user ?? null,
    });
  });

  app.delete("/api/session", (req, res) => {
    const sessionId = readCookie(req, SESSION_COOKIE);
    if (sessionId) deleteSession(db, sessionId);
    res
      .set("set-cookie", clearSessionCookie())
      .json({ schemaVersion: "acme.session.v1", signedOut: true });
  });

  app.get("/api/principal", (req, res) => {
    const principal = resolveRequestPrincipal(db, req, authMode, { allowAnonymousOff: true });
    if (!principal) return res.status(401).json({ error: "Authentication required" });
    res.json(principal);
  });

  app.post("/api/introspect", (req, res) => {
    const body = req.body as Record<string, unknown>;
    const token = text(body.token);
    if (!token) return res.status(400).json({ error: "token is required" });
    if (authMode === "off") {
      return res.json({ active: true, principal: devAdminPrincipal(db) });
    }
    const session = getSession(db, token);
    if (session) {
      const user = getUserById(db, session.userId);
      if (!user || !user.active) return res.json({ active: false });
      return res.json({ active: true, principal: principalFromUser(db, user, authMode) });
    }
    const service = findServiceToken(db, token);
    if (!service) return res.json({ active: false });
    return res.json({
      active: true,
      principal: principalFromService(db, service, authMode),
    });
  });

  app.get("/api/roles", requireAuth(db, authMode, "identity.read"), (_req, res) => {
    res.json(listRoles(db));
  });

  app.post("/api/roles", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    try {
      const body = req.body as Record<string, unknown>;
      const role = createRole(db, {
        slug: text(body.slug) ?? "",
        name: text(body.name) ?? "",
        description: typeof body.description === "string" ? body.description : "",
        permissions: stringArray(body.permissions),
      });
      res.status(201).json(role);
    } catch (error) {
      res.status(400).json({ error: errorMessage(error) });
    }
  });

  app.patch("/api/roles/:id", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    try {
      const body = req.body as Record<string, unknown>;
      const role = updateRole(db, numberId(req.params.id), {
        name: text(body.name),
        description: typeof body.description === "string" ? body.description : undefined,
        permissions: body.permissions !== undefined ? stringArray(body.permissions) : undefined,
      });
      if (!role) return res.status(404).json({ error: "Role not found" });
      res.json(role);
    } catch (error) {
      res.status(400).json({ error: errorMessage(error) });
    }
  });

  app.delete("/api/roles/:id", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    try {
      if (!deleteRole(db, numberId(req.params.id))) {
        return res.status(404).json({ error: "Role not found" });
      }
      res.status(204).end();
    } catch (error) {
      res.status(400).json({ error: errorMessage(error) });
    }
  });

  app.get("/api/users", requireAuth(db, authMode, "identity.read"), (_req, res) => {
    res.json(listUsers(db));
  });

  app.post("/api/users", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    try {
      const body = req.body as Record<string, unknown>;
      const user = createUser(db, {
        username: text(body.username) ?? "",
        displayName: text(body.displayName) ?? "",
        email: typeof body.email === "string" ? body.email : "",
        password: typeof body.password === "string" ? body.password : "",
        roleSlugs: stringArray(body.roleSlugs),
        active: typeof body.active === "boolean" ? body.active : undefined,
      });
      res.status(201).json(user);
    } catch (error) {
      res.status(400).json({ error: errorMessage(error) });
    }
  });

  app.get("/api/users/:id", requireAuth(db, authMode, "identity.read"), (req, res) => {
    const user = getUserById(db, numberId(req.params.id));
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  });

  app.patch("/api/users/:id", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    try {
      const body = req.body as Record<string, unknown>;
      const user = updateUser(db, numberId(req.params.id), {
        displayName: text(body.displayName),
        email: typeof body.email === "string" ? body.email : undefined,
        password: typeof body.password === "string" && body.password ? body.password : undefined,
        roleSlugs: body.roleSlugs !== undefined ? stringArray(body.roleSlugs) : undefined,
        active: typeof body.active === "boolean" ? body.active : undefined,
      });
      if (!user) return res.status(404).json({ error: "User not found" });
      res.json(user);
    } catch (error) {
      res.status(400).json({ error: errorMessage(error) });
    }
  });

  app.delete("/api/users/:id", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    if (!deleteUser(db, numberId(req.params.id))) {
      return res.status(404).json({ error: "User not found" });
    }
    res.status(204).end();
  });

  app.get("/api/tokens", requireAuth(db, authMode, "identity.admin"), (_req, res) => {
    res.json(listServiceTokens(db));
  });

  app.post("/api/tokens", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    try {
      const body = req.body as Record<string, unknown>;
      const token = createServiceTokenRecord(db, {
        name: text(body.name) ?? "",
        roleSlugs: stringArray(body.roleSlugs),
      });
      res.status(201).json(token);
    } catch (error) {
      res.status(400).json({ error: errorMessage(error) });
    }
  });

  app.delete("/api/tokens/:id", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    if (!deleteServiceToken(db, numberId(req.params.id))) {
      return res.status(404).json({ error: "Token not found" });
    }
    res.status(204).end();
  });

  app.get("*path", webIndex());
  return app;
}

export function startServer({
  db,
  port,
  host,
  authMode,
}: {
  db: Database.Database;
  port: number;
  host: string;
  authMode?: AuthMode;
}): Server {
  const mode = authMode ?? resolveAuthMode();
  const server = createApp({ db, authMode: mode }).listen(port, host, () => {
    console.log(
      `Acme Identity running at http://${host}:${port}` +
        `  (mode=${mode}${webFromSource() ? ", web from source" : ""})`,
    );
  });
  attachHmr(server);
  return server;
}

function requireAuth(db: Database.Database, authMode: AuthMode, permission: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const principal = resolveRequestPrincipal(db, req, authMode, { allowAnonymousOff: true });
    if (!principal) {
      return res.status(401).json({ error: "Authentication required" });
    }
    const allowed =
      hasPermission(principal, permission) ||
      (permission === "identity.admin" && principal.roles.includes("admin"));
    if (!allowed) {
      return res.status(403).json({ error: `Missing permission: ${permission}` });
    }
    (res.locals as Locals).principal = principal;
    next();
  };
}

function resolveRequestPrincipal(
  db: Database.Database,
  req: Request,
  authMode: AuthMode,
  opts: { allowAnonymousOff: boolean },
): Principal | undefined {
  if (authMode === "off" && opts.allowAnonymousOff) {
    return devAdminPrincipal(db);
  }

  const bearer = bearerToken(req.headers.authorization);
  if (bearer) {
    const session = getSession(db, bearer);
    if (session) {
      const user = getUserById(db, session.userId);
      if (user?.active) return principalFromUser(db, user, authMode);
    }
    const service = findServiceToken(db, bearer);
    if (service) return principalFromService(db, service, authMode);
  }

  const sessionId = readCookie(req, SESSION_COOKIE);
  if (sessionId) {
    const session = getSession(db, sessionId);
    if (session) {
      const user = getUserById(db, session.userId);
      if (user?.active) return principalFromUser(db, user, authMode);
    }
  }

  return undefined;
}

function bearerToken(authorization: string | undefined): string | undefined {
  if (!authorization) return undefined;
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || undefined;
}

function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [rawKey, ...rest] = part.trim().split("=");
    if (rawKey === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
}

function sessionCookie(sessionId: string, expiresAt: number): string {
  const maxAge = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
  return `${SESSION_COOKIE}=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.trim() !== "")
    .map((item) => item.trim());
}

function numberId(value: string | string[] | undefined): number {
  return Number(Array.isArray(value) ? value[0] : value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
