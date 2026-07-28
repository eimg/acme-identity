export const DEFAULT_PORT = 8317;
export const ISSUER = "acme-identity";
export const SESSION_COOKIE = "acme_identity_session";

/** Consumer / server auth mode. `off` resolves every caller as admin for local testing. */
export type AuthMode = "off" | "local";

export const SUITE_ROLE_SLUGS = ["admin", "operator", "member", "viewer"] as const;
export type SuiteRoleSlug = (typeof SUITE_ROLE_SLUGS)[number];

export interface Role {
  id: number;
  slug: string;
  name: string;
  description: string;
  permissions: string[];
  builtin: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface User {
  id: number;
  username: string;
  displayName: string;
  email: string;
  active: boolean;
  roleSlugs: string[];
  createdAt: number;
  updatedAt: number;
}

/** Stable principal contract for sibling apps (OIDC-shaped, local issuer today). */
export interface Principal {
  schemaVersion: "acme.principal.v1";
  sub: string;
  iss: string;
  username: string;
  displayName: string;
  email: string;
  roles: string[];
  permissions: string[];
  kind: "user" | "service" | "dev";
  authMode: AuthMode;
}

export interface SessionInfo {
  id: string;
  userId: number;
  createdAt: number;
  expiresAt: number;
}

export interface ServiceToken {
  id: number;
  name: string;
  tokenPrefix: string;
  roleSlugs: string[];
  createdAt: number;
  lastUsedAt: number | null;
  /** Present only at creation time. */
  token?: string;
}

export interface IdentityMeta {
  schemaVersion: "acme.identity.meta.v1";
  issuer: string;
  authMode: AuthMode;
  defaultDevPrincipal: "admin";
  roles: Array<{ slug: string; name: string; builtin: boolean }>;
}
