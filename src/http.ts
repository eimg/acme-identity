/**
 * Cross-cutting HTTP concerns for the identity API.
 *
 * The manage UI is cookie-authenticated and every sibling app runs on another
 * port of the same host, so `SameSite=Lax` alone does not stop a cross-origin
 * write from another local app: `localhost:8318` and `localhost:8316` are the
 * same site. State-changing requests are therefore origin-checked, with an
 * explicit allowlist for consumers that legitimately call identity from a
 * browser on another port.
 */
import type { NextFunction, Request, RequestHandler, Response } from "express";
import { DEV_USER_HEADER, SESSION_COOKIE } from "./types.js";

export interface HttpConfig {
  /** Origins allowed to make credentialed cross-origin calls, e.g. http://localhost:8318. */
  allowedOrigins: string[];
  /** `auto` marks the cookie Secure only when the request arrived over https. */
  cookieSecure: boolean | "auto";
  trustProxy: boolean;
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function resolveHttpConfig(env: NodeJS.ProcessEnv = process.env): HttpConfig {
  const secure = env.ACME_IDENTITY_COOKIE_SECURE?.trim().toLowerCase();
  return {
    allowedOrigins: (env.ACME_IDENTITY_ALLOWED_ORIGINS ?? "")
      .split(",")
      .map((origin) => origin.trim().replace(/\/$/, ""))
      .filter(Boolean),
    cookieSecure: secure === "1" || secure === "true" ? true : secure === "0" ? false : "auto",
    trustProxy: env.ACME_IDENTITY_TRUST_PROXY === "1",
  };
}

export function securityHeaders(): RequestHandler {
  return (req, res, next) => {
    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader("referrer-policy", "no-referrer");
    res.setHeader("x-frame-options", "DENY");
    // Principals and token lists must never sit in a shared or browser cache.
    if (req.path.startsWith("/api/")) res.setHeader("cache-control", "no-store");
    next();
  };
}

/**
 * Opt-in credentialed CORS. Off by default: consumers normally resolve principals
 * server-side. Sibling apps that call identity straight from the browser add
 * their origin to `ACME_IDENTITY_ALLOWED_ORIGINS`, which also whitelists them in
 * the origin guard below.
 */
export function cors(config: HttpConfig): RequestHandler {
  return (req, res, next) => {
    const origin = req.headers.origin?.replace(/\/$/, "");
    const allowed = Boolean(origin && config.allowedOrigins.includes(origin));
    res.vary("Origin");
    if (allowed) {
      res.setHeader("access-control-allow-origin", req.headers.origin!);
      res.setHeader("access-control-allow-credentials", "true");
      res.setHeader("access-control-allow-methods", "GET,POST,PATCH,DELETE,OPTIONS");
      res.setHeader("access-control-allow-headers", `content-type,authorization,${DEV_USER_HEADER}`);
      res.setHeader("access-control-max-age", "600");
    }
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  };
}

/** Rejects cross-origin writes that a browser could trigger with the session cookie. */
export function sameOriginGuard(config: HttpConfig): RequestHandler {
  return (req, res, next) => {
    if (SAFE_METHODS.has(req.method)) return next();
    const origin = req.headers.origin;
    const site = req.headers["sec-fetch-site"];

    if (typeof site === "string" && (site === "same-origin" || site === "none")) return next();
    if (!origin) {
      // No Origin means no browser initiated this; a forged cross-site request always sends one.
      return next();
    }
    const normalized = origin.replace(/\/$/, "");
    if (config.allowedOrigins.includes(normalized)) return next();
    if (normalized === selfOrigin(req)) return next();
    res.status(403).json({
      error: "Cross-origin request blocked",
      hint: "Add the origin to ACME_IDENTITY_ALLOWED_ORIGINS to allow it",
    });
  };
}

export function sessionCookie(req: Request, config: HttpConfig, sessionId: string, expiresAt: number): string {
  const maxAge = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
  return serializeCookie(req, config, encodeURIComponent(sessionId), maxAge);
}

export function clearSessionCookie(req: Request, config: HttpConfig): string {
  return serializeCookie(req, config, "", 0);
}

function serializeCookie(req: Request, config: HttpConfig, value: string, maxAge: number): string {
  const secure = config.cookieSecure === "auto" ? isHttps(req) : config.cookieSecure;
  const parts = [
    `${SESSION_COOKIE}=${value}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${maxAge}`,
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

export function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [rawKey, ...rest] = part.trim().split("=");
    if (rawKey === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
}

export function bearerToken(authorization: string | undefined): string | undefined {
  if (!authorization) return undefined;
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || undefined;
}

/**
 * Per-username/per-IP failure counter. In-memory on purpose: a restart clearing
 * it is acceptable, and it keeps password guessing from being limited only by
 * KDF cost.
 */
export class LoginThrottle {
  private readonly attempts = new Map<string, { failures: number; firstAt: number }>();

  constructor(
    private readonly maxFailures = 10,
    private readonly windowMs = 15 * 60_000,
    private readonly maxKeys = 5_000,
  ) {}

  private key(req: Request, username: string): string {
    return `${req.ip ?? "unknown"}|${username.trim().toLowerCase()}`;
  }

  /** Seconds the caller must wait, or 0 when the attempt may proceed. */
  retryAfter(req: Request, username: string): number {
    const entry = this.attempts.get(this.key(req, username));
    if (!entry || entry.failures < this.maxFailures) return 0;
    const remaining = entry.firstAt + this.windowMs - Date.now();
    if (remaining <= 0) {
      this.attempts.delete(this.key(req, username));
      return 0;
    }
    return Math.ceil(remaining / 1000);
  }

  recordFailure(req: Request, username: string): void {
    if (this.attempts.size > this.maxKeys) this.prune();
    const key = this.key(req, username);
    const entry = this.attempts.get(key);
    if (!entry || Date.now() - entry.firstAt > this.windowMs) {
      this.attempts.set(key, { failures: 1, firstAt: Date.now() });
      return;
    }
    entry.failures += 1;
  }

  recordSuccess(req: Request, username: string): void {
    this.attempts.delete(this.key(req, username));
  }

  private prune(): void {
    const cutoff = Date.now() - this.windowMs;
    for (const [key, entry] of this.attempts) {
      if (entry.firstAt < cutoff) this.attempts.delete(key);
    }
    if (this.attempts.size > this.maxKeys) this.attempts.clear();
  }
}

/** Terminal handler so consumers always parse JSON, never an HTML error page. */
export function jsonErrorHandler() {
  return (error: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) return next(error);
    const status = statusFor(error);
    if (status >= 500) console.error("identity request failed:", error);
    res.status(status).json({ error: status >= 500 ? "Internal error" : messageFor(error) });
  };
}

function statusFor(error: unknown): number {
  const candidate = (error as { status?: number; statusCode?: number } | null) ?? {};
  const status = candidate.status ?? candidate.statusCode;
  return typeof status === "number" && status >= 400 && status < 600 ? status : 500;
}

function messageFor(error: unknown): string {
  return error instanceof Error ? error.message : "Request failed";
}

/** `req.protocol` already honours `x-forwarded-proto` when trust proxy is enabled. */
function isHttps(req: Request): boolean {
  return req.protocol === "https";
}

function selfOrigin(req: Request): string {
  const host = req.headers.host;
  return host ? `${isHttps(req) ? "https" : "http"}://${host}` : "";
}
