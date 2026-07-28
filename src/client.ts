/**
 * Consumer helper for sibling Acme apps.
 *
 * In `ACME_AUTH_MODE=off` an anonymous caller resolves locally with no network
 * hop, so a sibling app's feature tests never depend on identity being up. A
 * caller that does present a credential (or names a dev principal) is resolved
 * against the identity service so role gates can be exercised in off mode too.
 *
 * In `local` mode every request resolves against `GET /api/principal`.
 */
import type { AuthMode, Principal } from "./types.js";
import { DEV_USER_HEADER, SESSION_COOKIE } from "./types.js";

export {
  grants,
  hasAllPermissions,
  hasAnyPermission,
  hasPermission,
  hasRole,
  isSuiteAdmin,
  isValidPermission,
  normalizePermission,
  type PermissionHolder,
} from "./permissions.js";
export { DEV_USER_HEADER, SESSION_COOKIE } from "./types.js";
export type { AuthMode, Principal } from "./types.js";

export type FetchFn = typeof fetch;

/**
 * `unauthenticated` — the caller has no valid credential; answer 401.
 * `unavailable`     — identity could not be reached; answer 503, do not treat as anonymous.
 * `config`          — the consumer is misconfigured.
 */
export type IdentityErrorCode = "unauthenticated" | "unavailable" | "config";

export class IdentityClientError extends Error {
  constructor(
    message: string,
    readonly code: IdentityErrorCode = "unavailable",
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "IdentityClientError";
  }
}

export interface ResolveOptions {
  fetchFn?: FetchFn;
  identityUrl?: string;
  authMode?: AuthMode;
  authorization?: string | null;
  cookie?: string | null;
  /** Off mode only: resolve as this seeded user instead of admin. */
  devUser?: string | null;
  timeoutMs?: number;
}

export function resolveConsumerAuthMode(raw = process.env.ACME_AUTH_MODE): AuthMode {
  const value = (raw ?? "off").trim().toLowerCase();
  if (value === "off" || value === "local") return value;
  throw new IdentityClientError(
    `ACME_AUTH_MODE must be "off" or "local" (got ${JSON.stringify(raw)})`,
    "config",
  );
}

/** Sibling apps default to off so feature tests run as admin without identity up. */
export function defaultConsumerAuthMode(): AuthMode {
  try {
    return resolveConsumerAuthMode();
  } catch {
    return "off";
  }
}

export function identityBaseUrl(
  raw = process.env.ACME_IDENTITY_URL ?? "http://127.0.0.1:8317",
): string {
  return raw.replace(/\/$/, "");
}

export function localAdminFallback(authMode: AuthMode = "off"): Principal {
  return {
    schemaVersion: "acme.principal.v1",
    sub: "dev:admin",
    iss: "acme-identity",
    username: "admin",
    displayName: "Acme Admin",
    email: "admin@acme.local",
    roles: ["admin"],
    permissions: ["*"],
    kind: "dev",
    authMode,
  };
}

/**
 * Throws `IdentityClientError` when no principal can be resolved. Consumers
 * should map `code === "unavailable"` to 503 rather than 401, so an identity
 * outage is never mistaken for a signed-out user.
 */
export async function resolvePrincipal(options: ResolveOptions = {}): Promise<Principal> {
  const authMode = options.authMode ?? defaultConsumerAuthMode();
  if (authMode === "off" && !hasCredential(options)) {
    return localAdminFallback("off");
  }

  let principal: Principal | null = null;
  try {
    principal = await fetchPrincipal(options);
  } catch (error) {
    if (authMode === "off") return localAdminFallback("off");
    throw error;
  }
  if (principal) return principal;
  if (authMode === "off") return localAdminFallback("off");
  throw new IdentityClientError("Authentication required", "unauthenticated");
}

/** Null instead of throwing for the `unauthenticated` case; still throws when identity is down. */
export async function resolveOptionalPrincipal(
  options: ResolveOptions = {},
): Promise<Principal | null> {
  try {
    return await resolvePrincipal(options);
  } catch (error) {
    if (error instanceof IdentityClientError && error.code === "unauthenticated") return null;
    throw error;
  }
}

async function fetchPrincipal(options: ResolveOptions): Promise<Principal | null> {
  const fetchFn = options.fetchFn ?? fetch;
  const headers: Record<string, string> = {};
  if (options.authorization) headers.authorization = options.authorization;
  if (options.cookie) headers.cookie = options.cookie;
  if (options.devUser) headers[DEV_USER_HEADER] = options.devUser;

  let response: Response;
  try {
    response = await fetchFn(`${identityBaseUrl(options.identityUrl)}/api/principal`, {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(options.timeoutMs ?? 3_000),
    });
  } catch (error) {
    throw new IdentityClientError(
      `Identity service unreachable at ${identityBaseUrl(options.identityUrl)}`,
      "unavailable",
      { cause: error },
    );
  }
  if (response.status === 401) return null;
  if (!response.ok) {
    throw new IdentityClientError(
      `Identity principal lookup failed (${response.status})`,
      "unavailable",
    );
  }
  return (await response.json()) as Principal;
}

/** An unrelated cookie on the request is not a credential, so it must not force a lookup. */
function hasCredential(options: ResolveOptions): boolean {
  if (options.authorization?.trim()) return true;
  if (options.devUser?.trim()) return true;
  return Boolean(options.cookie && options.cookie.includes(`${SESSION_COOKIE}=`));
}

export function bearerFromRequest(authorization: string | undefined): string | undefined {
  if (!authorization) return undefined;
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || undefined;
}
