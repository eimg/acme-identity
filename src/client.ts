/**
 * Consumer helper for sibling Acme apps.
 *
 * In ACME_AUTH_MODE=off, always returns the identity service's dev admin principal
 * (or a local fallback if identity is unreachable). In local mode, resolves via
 * session cookie or Bearer token against the identity HTTP API.
 */
import type { AuthMode, Principal } from "./types.js";

export type FetchFn = typeof fetch;

export class IdentityClientError extends Error {}

export function resolveConsumerAuthMode(raw = process.env.ACME_AUTH_MODE): AuthMode {
  const value = (raw ?? "off").trim().toLowerCase();
  if (value === "off" || value === "local") return value;
  throw new IdentityClientError(
    `ACME_AUTH_MODE must be "off" or "local" (got ${JSON.stringify(raw)})`,
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

export async function resolvePrincipal(options: {
  fetchFn?: FetchFn;
  identityUrl?: string;
  authMode?: AuthMode;
  authorization?: string | null;
  cookie?: string | null;
}): Promise<Principal> {
  const authMode = options.authMode ?? defaultConsumerAuthMode();
  if (authMode === "off") {
    const fetched = await tryFetchPrincipal(options).catch(() => null);
    return fetched ?? localAdminFallback("off");
  }

  const principal = await tryFetchPrincipal(options);
  if (!principal) {
    throw new IdentityClientError("Authentication required");
  }
  return principal;
}

async function tryFetchPrincipal(options: {
  fetchFn?: FetchFn;
  identityUrl?: string;
  authorization?: string | null;
  cookie?: string | null;
}): Promise<Principal | null> {
  const fetchFn = options.fetchFn ?? fetch;
  const headers: Record<string, string> = {};
  if (options.authorization) headers.authorization = options.authorization;
  if (options.cookie) headers.cookie = options.cookie;
  const response = await fetchFn(`${identityBaseUrl(options.identityUrl)}/api/principal`, {
    method: "GET",
    headers,
    signal: AbortSignal.timeout(3_000),
  });
  if (response.status === 401) return null;
  if (!response.ok) {
    throw new IdentityClientError(`Identity principal lookup failed (${response.status})`);
  }
  return (await response.json()) as Principal;
}

export function bearerFromRequest(authorization: string | undefined): string | undefined {
  if (!authorization) return undefined;
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || undefined;
}
