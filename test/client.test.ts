import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  IdentityClientError,
  resolveConsumerAuthMode,
  resolveOptionalPrincipal,
  resolvePrincipal,
} from "../src/client.js";
import { DEV_USER_HEADER, SESSION_COOKIE } from "../src/types.js";
import type { Principal } from "../src/types.js";

function stubFetch(handler: (url: string, init: RequestInit) => Response) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchFn = (async (url: unknown, init: unknown) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return handler(String(url), (init ?? {}) as RequestInit);
  }) as typeof fetch;
  return { fetchFn, calls };
}

const principal = (overrides: Partial<Principal> = {}): Principal => ({
  schemaVersion: "acme.principal.v1",
  sub: "user:3",
  iss: "acme-identity",
  username: "viewer",
  displayName: "Acme Viewer",
  email: "viewer@acme.local",
  roles: ["viewer"],
  permissions: ["identity.read"],
  kind: "user",
  authMode: "local",
  ...overrides,
});

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

describe("consumer client", () => {
  it("resolves anonymous off-mode callers with no network hop", async () => {
    const { fetchFn, calls } = stubFetch(() => json(principal()));
    const resolved = await resolvePrincipal({ authMode: "off", fetchFn });
    assert.equal(calls.length, 0, "off mode must not require identity to be running");
    assert.equal(resolved.kind, "dev");
    assert.deepEqual(resolved.permissions, ["*"]);
  });

  it("ignores unrelated cookies when deciding whether a credential is present", async () => {
    const { fetchFn, calls } = stubFetch(() => json(principal()));
    await resolvePrincipal({ authMode: "off", fetchFn, cookie: "theme=dark; other=1" });
    assert.equal(calls.length, 0);

    await resolvePrincipal({ authMode: "off", fetchFn, cookie: `${SESSION_COOKIE}=sess_abc` });
    assert.equal(calls.length, 1, "a real session cookie should be resolved upstream");
  });

  it("forwards a named dev principal in off mode", async () => {
    const { fetchFn, calls } = stubFetch(() => json(principal({ kind: "dev", authMode: "off" })));
    const resolved = await resolvePrincipal({ authMode: "off", fetchFn, devUser: "viewer" });
    assert.equal(calls.length, 1);
    assert.equal(
      (calls[0].init.headers as Record<string, string>)[DEV_USER_HEADER],
      "viewer",
    );
    assert.deepEqual(resolved.roles, ["viewer"]);
  });

  it("falls back to admin in off mode when identity is unreachable", async () => {
    const { fetchFn } = stubFetch(() => {
      throw new Error("ECONNREFUSED");
    });
    const resolved = await resolvePrincipal({
      authMode: "off",
      fetchFn,
      cookie: `${SESSION_COOKIE}=sess_abc`,
    });
    assert.equal(resolved.kind, "dev");
  });

  it("distinguishes an unauthenticated caller from an unreachable service", async () => {
    const unauthenticated = stubFetch(() => json({ error: "Authentication required" }, 401));
    await assert.rejects(
      () => resolvePrincipal({ authMode: "local", fetchFn: unauthenticated.fetchFn }),
      (error: unknown) =>
        error instanceof IdentityClientError && error.code === "unauthenticated",
    );

    const down = stubFetch(() => {
      throw new Error("ECONNREFUSED");
    });
    await assert.rejects(
      () => resolvePrincipal({ authMode: "local", fetchFn: down.fetchFn }),
      (error: unknown) => error instanceof IdentityClientError && error.code === "unavailable",
    );
  });

  it("returns null for signed-out callers but still throws when identity is down", async () => {
    const unauthenticated = stubFetch(() => json({ error: "nope" }, 401));
    assert.equal(
      await resolveOptionalPrincipal({ authMode: "local", fetchFn: unauthenticated.fetchFn }),
      null,
    );

    const down = stubFetch(() => json({ error: "boom" }, 500));
    await assert.rejects(() =>
      resolveOptionalPrincipal({ authMode: "local", fetchFn: down.fetchFn }),
    );
  });

  it("rejects an invalid ACME_AUTH_MODE as a configuration error", () => {
    assert.throws(
      () => resolveConsumerAuthMode("kerberos"),
      (error: unknown) => error instanceof IdentityClientError && error.code === "config",
    );
  });
});
