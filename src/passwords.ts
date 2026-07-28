/**
 * Secret hashing for the two very different secrets this service stores.
 *
 * Human passwords are low entropy, so they get a slow salted KDF (scrypt).
 * Service tokens are 384 random bits minted by us, so brute forcing a stored
 * digest is infeasible and a slow KDF buys nothing — they get an unsalted
 * SHA-256 digest instead. That difference is what lets token lookup be a single
 * indexed query instead of a KDF pass over every token row.
 */
import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const SCRYPT_KEYLEN = 64;

/** Verified against on failed logins so an unknown user costs the same as a wrong password. */
export const DUMMY_PASSWORD_HASH = hashPassword(randomBytes(32).toString("hex"));

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, SCRYPT_KEYLEN).toString("hex");
  return `scrypt$${salt}$${hash}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [algo, salt, hash] = stored.split("$");
  if (algo !== "scrypt" || !salt || !hash) return false;
  const actual = scryptSync(password, salt, SCRYPT_KEYLEN);
  const expected = Buffer.from(hash, "hex");
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}

export function newSessionId(): string {
  return `sess_${randomBytes(24).toString("hex")}`;
}

export function newServiceToken(): string {
  return `svc_${randomBytes(48).toString("hex")}`;
}

/** Deterministic digest so a presented token maps straight to its row via a unique index. */
export function hashToken(token: string): string {
  return `sha256$${createHash("sha256").update(token, "utf8").digest("hex")}`;
}

export function verifyToken(token: string, stored: string): boolean {
  if (stored.startsWith("scrypt$")) return verifyPassword(token, stored);
  return timingSafeEqualUtf8(hashToken(token), stored);
}

export function isLegacyTokenHash(stored: string): boolean {
  return stored.startsWith("scrypt$");
}

export function tokenPrefix(token: string): string {
  return token.slice(0, 12);
}

function timingSafeEqualUtf8(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
