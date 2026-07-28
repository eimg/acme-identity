import type { AuthMode } from "./types.js";

export function resolveAuthMode(raw = process.env.ACME_AUTH_MODE): AuthMode {
  const value = (raw ?? "local").trim().toLowerCase();
  if (value === "off" || value === "local") return value;
  throw new Error(`ACME_AUTH_MODE must be "off" or "local" (got ${JSON.stringify(raw)})`);
}

export function assertInsecureModeAllowed(mode: AuthMode): void {
  if (mode !== "off") return;
  const allow =
    process.env.ACME_ALLOW_INSECURE === "1" ||
    process.env.NODE_ENV === "test" ||
    process.env.ACME_IDENTITY_DEV === "1";
  if (!allow) {
    throw new Error(
      'ACME_AUTH_MODE=off requires ACME_ALLOW_INSECURE=1 (or NODE_ENV=test / ACME_IDENTITY_DEV=1)',
    );
  }
}
