import express, { type Express, type NextFunction, type Request, type Response } from "express";
import type { Server } from "node:http";
import type Database from "better-sqlite3";
import {
  LoginThrottle,
  type HttpConfig,
  bearerToken,
  clearSessionCookie,
  cors,
  jsonErrorHandler,
  readCookie,
  resolveHttpConfig,
  sameOriginGuard,
  securityHeaders,
  sessionCookie,
} from "./http.js";
import { assertInsecureModeAllowed, resolveAuthMode } from "./mode.js";
import { hasPermission } from "./permissions.js";
import {
  devAdminPrincipal,
  devPrincipalFor,
  principalFromService,
  principalFromUser,
} from "./principal.js";
import { PERMISSION_VOCABULARY, usingSeedAdminPassword } from "./seed.js";
import {
  authenticateUser,
  countSessionsForUser,
  createRole,
  createServiceTokenRecord,
  createSession,
  createUser,
  deleteRole,
  deleteServiceToken,
  deleteSession,
  deleteSessionsForUser,
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
import { DEV_USER_HEADER, ISSUER, SESSION_COOKIE } from "./types.js";
import { attachHmr, webAssets, webFromSource, webIndex } from "./webAssets.js";

type Locals = {
  principal?: Principal;
};

export function createApp({
  db,
  authMode = resolveAuthMode(),
  http = resolveHttpConfig(),
}: {
  db: Database.Database;
  authMode?: AuthMode;
  http?: HttpConfig;
}): Express {
  assertInsecureModeAllowed(authMode);
  const app = express();
  const throttle = new LoginThrottle();
  if (http.trustProxy) app.set("trust proxy", true);
  app.use(securityHeaders());
  app.use("/api", cors(http));
  app.use(express.json({ limit: "64kb" }));
  app.use("/api", sameOriginGuard(http));
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
      sessionCookie: SESSION_COOKIE,
      devUserHeader: DEV_USER_HEADER,
      roles: listRoles(db).map((role) => ({
        slug: role.slug,
        name: role.name,
        builtin: role.builtin,
      })),
      permissions: PERMISSION_VOCABULARY,
    });
  });

  app.post("/api/session", (req, res) => {
    const body = req.body as Record<string, unknown>;
    const username = text(body.username);
    const password = typeof body.password === "string" ? body.password : "";
    if (!username || !password) {
      return res.status(400).json({ error: "username and password are required" });
    }
    const retryAfter = throttle.retryAfter(req, username);
    if (retryAfter > 0) {
      return res
        .status(429)
        .set("retry-after", String(retryAfter))
        .json({ error: `Too many failed attempts. Retry in ${retryAfter}s` });
    }
    const user = authenticateUser(db, username, password);
    if (!user) {
      throttle.recordFailure(req, username);
      return res.status(401).json({ error: "Invalid username or password" });
    }
    throttle.recordSuccess(req, username);
    const session = createSession(db, user.id);
    const principal = principalFromUser(db, user, authMode);
    res
      .append("set-cookie", sessionCookie(req, http, session.id, session.expiresAt))
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
    const principal = resolvePrincipal(db, req, authMode);
    if (!principal) return res.status(401).json({ error: "Not signed in" });
    res.json({
      schemaVersion: "acme.session.v1",
      principal,
      user: userForPrincipal(db, principal) ?? null,
    });
  });

  app.delete("/api/session", (req, res) => {
    const sessionId = readCookie(req, SESSION_COOKIE);
    if (sessionId) deleteSession(db, sessionId);
    res
      .append("set-cookie", clearSessionCookie(req, http))
      .json({ schemaVersion: "acme.session.v1", signedOut: true });
  });

  /** Password self-service, so rotating a credential does not require an admin. */
  app.post("/api/session/password", requireAuth(db, authMode), (req, res) => {
    const principal = (res.locals as Locals).principal!;
    const body = req.body as Record<string, unknown>;
    const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
    const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";
    if (principal.kind !== "user") {
      return res.status(403).json({ error: "Only interactive users can change a password" });
    }
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "currentPassword and newPassword are required" });
    }
    const user = userForPrincipal(db, principal);
    if (!user || !authenticateUser(db, user.username, currentPassword)) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }
    updateUser(db, user.id, { password: newPassword });
    // updateUser revokes every session for the user, including this one.
    res
      .append("set-cookie", clearSessionCookie(req, http))
      .json({ schemaVersion: "acme.session.v1", passwordChanged: true, signedOut: true });
  });

  app.get("/api/principal", (req, res) => {
    const principal = resolvePrincipal(db, req, authMode);
    if (!principal) return res.status(401).json({ error: "Authentication required" });
    res.json(principal);
  });

  /**
   * Token validation for callers that cannot forward cookies. Authenticated
   * (RFC 7662) so it is not an open oracle for probing token validity.
   */
  app.post("/api/introspect", requireAuth(db, authMode, "identity.read"), (req, res) => {
    const body = req.body as Record<string, unknown>;
    const token = text(body.token);
    if (!token) return res.status(400).json({ error: "token is required" });
    if (authMode === "off") {
      return res.json({ active: true, principal: devAdminPrincipal(db) });
    }
    const principal = principalForCredential(db, token, authMode);
    res.json(principal ? { active: true, principal } : { active: false });
  });

  app.get("/api/roles", requireAuth(db, authMode, "identity.read"), (_req, res) => {
    res.json(listRoles(db));
  });

  app.post("/api/roles", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    const body = req.body as Record<string, unknown>;
    const role = createRole(db, {
      slug: text(body.slug) ?? "",
      name: text(body.name) ?? "",
      description: typeof body.description === "string" ? body.description : "",
      permissions: stringArray(body.permissions),
    });
    res.status(201).json(role);
  });

  app.patch("/api/roles/:id", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    const body = req.body as Record<string, unknown>;
    const role = updateRole(db, numberId(req.params.id), {
      name: text(body.name),
      description: typeof body.description === "string" ? body.description : undefined,
      permissions: body.permissions !== undefined ? stringArray(body.permissions) : undefined,
    });
    if (!role) return res.status(404).json({ error: "Role not found" });
    res.json(role);
  });

  app.delete("/api/roles/:id", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    if (!deleteRole(db, numberId(req.params.id))) {
      return res.status(404).json({ error: "Role not found" });
    }
    res.status(204).end();
  });

  app.get("/api/users", requireAuth(db, authMode, "identity.read"), (_req, res) => {
    res.json(listUsers(db));
  });

  app.post("/api/users", requireAuth(db, authMode, "identity.admin"), (req, res) => {
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
  });

  app.get("/api/users/:id", requireAuth(db, authMode, "identity.read"), (req, res) => {
    const user = getUserById(db, numberId(req.params.id));
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  });

  app.patch("/api/users/:id", requireAuth(db, authMode, "identity.admin"), (req, res) => {
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
  });

  app.delete("/api/users/:id", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    if (!deleteUser(db, numberId(req.params.id))) {
      return res.status(404).json({ error: "User not found" });
    }
    res.status(204).end();
  });

  app.get("/api/users/:id/sessions", requireAuth(db, authMode, "identity.read"), (req, res) => {
    const user = getUserById(db, numberId(req.params.id));
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ userId: user.id, active: countSessionsForUser(db, user.id) });
  });

  app.delete("/api/users/:id/sessions", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    const user = getUserById(db, numberId(req.params.id));
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ userId: user.id, revoked: deleteSessionsForUser(db, user.id) });
  });

  app.get("/api/tokens", requireAuth(db, authMode, "identity.admin"), (_req, res) => {
    res.json(listServiceTokens(db));
  });

  app.post("/api/tokens", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    const body = req.body as Record<string, unknown>;
    const token = createServiceTokenRecord(db, {
      name: text(body.name) ?? "",
      roleSlugs: stringArray(body.roleSlugs),
      expiresAt: expiryFromBody(body),
    });
    res.status(201).json(token);
  });

  app.delete("/api/tokens/:id", requireAuth(db, authMode, "identity.admin"), (req, res) => {
    if (!deleteServiceToken(db, numberId(req.params.id))) {
      return res.status(404).json({ error: "Token not found" });
    }
    res.status(204).end();
  });

  // Unknown API paths must not fall through to the SPA shell: a consumer calling
  // a mistyped endpoint should see a JSON 404, not HTML with a 200.
  app.all("/api/*path", (req, res) => {
    res.status(404).json({ error: `Unknown endpoint: ${req.method} ${req.path}` });
  });

  app.get("*path", webIndex());
  app.use(jsonErrorHandler());
  return app;
}

export function startServer({
  db,
  port,
  host,
  authMode,
  http = resolveHttpConfig(),
}: {
  db: Database.Database;
  port: number;
  host: string;
  authMode?: AuthMode;
  http?: HttpConfig;
}): Server {
  const mode = authMode ?? resolveAuthMode();
  const server = createApp({ db, authMode: mode, http }).listen(port, host, () => {
    console.log(
      `Acme Identity running at http://${host}:${port}` +
        `  (mode=${mode}${webFromSource() ? ", web from source" : ""})`,
    );
    warnOnExposedSeedCredentials(db, host, mode);
  });
  attachHmr(server);
  return server;
}

/** Reachable from another machine with `admin`/`admin` still set is worth shouting about. */
function warnOnExposedSeedCredentials(
  db: Database.Database,
  host: string,
  authMode: AuthMode,
): void {
  const loopback = host === "127.0.0.1" || host === "localhost" || host === "::1";
  if (loopback || !usingSeedAdminPassword(db)) return;
  console.warn(
    `WARNING: bound to ${host} with the seeded admin password still in place` +
      (authMode === "off" ? " and ACME_AUTH_MODE=off" : "") +
      ". Set ACME_IDENTITY_ADMIN_PASSWORD before seeding, or run `acme-identity set-password admin`.",
  );
}

function requireAuth(db: Database.Database, authMode: AuthMode, permission?: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const principal = resolvePrincipal(db, req, authMode);
    if (!principal) {
      return res.status(401).json({ error: "Authentication required" });
    }
    if (permission && !hasPermission(principal, permission)) {
      return res.status(403).json({ error: `Missing permission: ${permission}` });
    }
    (res.locals as Locals).principal = principal;
    next();
  };
}

function resolvePrincipal(
  db: Database.Database,
  req: Request,
  authMode: AuthMode,
): Principal | undefined {
  if (authMode === "off") {
    const requested =
      headerValue(req, DEV_USER_HEADER) ?? process.env.ACME_DEV_PRINCIPAL?.trim() ?? "admin";
    return devPrincipalFor(db, requested);
  }

  const bearer = bearerToken(req.headers.authorization);
  if (bearer) {
    const principal = principalForCredential(db, bearer, authMode);
    if (principal) return principal;
  }

  const sessionId = readCookie(req, SESSION_COOKIE);
  if (sessionId) return principalForSession(db, sessionId, authMode);
  return undefined;
}

/** Resolves either credential shape; the prefix avoids probing the wrong table first. */
function principalForCredential(
  db: Database.Database,
  credential: string,
  authMode: AuthMode,
): Principal | undefined {
  if (!credential.startsWith("svc_")) {
    const fromSession = principalForSession(db, credential, authMode);
    if (fromSession || credential.startsWith("sess_")) return fromSession;
  }
  const service = findServiceToken(db, credential);
  return service ? principalFromService(db, service, authMode) : undefined;
}

function principalForSession(
  db: Database.Database,
  sessionId: string,
  authMode: AuthMode,
): Principal | undefined {
  const session = getSession(db, sessionId);
  if (!session) return undefined;
  const user = getUserById(db, session.userId);
  return user?.active ? principalFromUser(db, user, authMode) : undefined;
}

function userForPrincipal(db: Database.Database, principal: Principal) {
  const match = /^user:(\d+)$/.exec(principal.sub);
  return match ? getUserById(db, Number(match[1])) : undefined;
}

function headerValue(req: Request, name: string): string | undefined {
  const value = req.headers[name];
  const raw = Array.isArray(value) ? value[0] : value;
  return raw?.trim() || undefined;
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
  const raw = Array.isArray(value) ? value[0] : value;
  const id = Number(raw);
  return Number.isInteger(id) ? id : Number.NaN;
}

function expiryFromBody(body: Record<string, unknown>): number | null {
  if (typeof body.expiresAt === "number") return body.expiresAt;
  if (typeof body.expiresInDays === "number" && body.expiresInDays > 0) {
    return Date.now() + body.expiresInDays * 86_400_000;
  }
  return null;
}
