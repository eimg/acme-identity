import { after, before, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { createApp } from "../src/app.js";
import { openDatabase } from "../src/db.js";
import { resolveHttpConfig } from "../src/http.js";
import { localAdminFallback, resolveConsumerAuthMode } from "../src/client.js";
import { DEV_USER_HEADER, SESSION_COOKIE } from "../src/types.js";
import { seedIfEmpty } from "../src/seed.js";

const http = resolveHttpConfig({} as NodeJS.ProcessEnv);

describe("acme-identity API", () => {
  let dataDir: string;
  let db: ReturnType<typeof openDatabase>;

  before(() => {
    process.env.ACME_ALLOW_INSECURE = "1";
    dataDir = mkdtempSync(join(tmpdir(), "acme-identity-"));
    db = openDatabase(dataDir);
  });

  after(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  const off = () => createApp({ db, authMode: "off", http });
  const local = () => createApp({ db, authMode: "local", http });

  const signIn = async (username: string, password = username) => {
    const login = await request(local())
      .post("/api/session")
      .send({ username, password });
    assert.equal(login.status, 201, `sign-in for ${username} failed: ${login.text}`);
    return login.headers["set-cookie"] as unknown as string[];
  };

  it("seeds builtin roles and users", async () => {
    const roles = await request(off()).get("/api/roles");
    assert.equal(roles.status, 200);
    assert.deepEqual(
      roles.body.map((role: { slug: string }) => role.slug).sort(),
      ["admin", "member", "operator", "viewer"],
    );

    const users = await request(off()).get("/api/users");
    assert.equal(users.status, 200);
    assert.equal(users.body.length, 13);
    assert.ok(users.body.some((user: { username: string; email: string }) =>
      user.username === "maya.chen" && user.email === "maya.chen@acme.test"));
  });

  it("adds Primer actor accounts and the operator capability to an existing database", () => {
    db.prepare("DELETE FROM users WHERE username = 'maya.chen'").run();
    const operator = db.prepare("SELECT permissions_json FROM roles WHERE slug = 'operator'")
      .get() as { permissions_json: string };
    db.prepare("UPDATE roles SET permissions_json = ? WHERE slug = 'operator'")
      .run(JSON.stringify((JSON.parse(operator.permissions_json) as string[]).filter((key) => key !== "primer.manage")));

    seedIfEmpty(db);

    assert.ok(db.prepare("SELECT 1 FROM users WHERE username = 'maya.chen'").get());
    const updated = db.prepare("SELECT permissions_json FROM roles WHERE slug = 'operator'")
      .get() as { permissions_json: string };
    assert.ok((JSON.parse(updated.permissions_json) as string[]).includes("primer.manage"));
  });

  it("publishes the gate vocabulary and cookie name in meta", async () => {
    const meta = await request(off()).get("/api/meta");
    assert.equal(meta.status, 200);
    assert.equal(meta.body.sessionCookie, SESSION_COOKIE);
    assert.equal(meta.body.devUserHeader, DEV_USER_HEADER);
    const keys = meta.body.permissions.map((entry: { key: string }) => entry.key);
    assert.ok(keys.includes("identity.admin"));
    assert.ok(keys.includes("prelude.write"));
    assert.ok(keys.includes("primer.manage"));
    assert.ok(keys.includes("observability.read"));
    assert.ok(keys.includes("observability.collect"));
    assert.ok(keys.includes("observability.manage"));
  });

  it("resolves anonymous callers as admin when mode=off", async () => {
    const principal = await request(off()).get("/api/principal");
    assert.equal(principal.status, 200);
    assert.equal(principal.body.kind, "dev");
    assert.deepEqual(principal.body.roles, ["admin"]);
    assert.ok(principal.body.permissions.includes("*"));
  });

  it("impersonates a seeded user in mode=off for consumer role tests", async () => {
    const viewer = await request(off()).get("/api/principal").set(DEV_USER_HEADER, "viewer");
    assert.equal(viewer.status, 200);
    assert.equal(viewer.body.kind, "dev");
    assert.deepEqual(viewer.body.roles, ["viewer"]);
    assert.ok(!viewer.body.permissions.includes("*"));

    const denied = await request(off())
      .post("/api/roles")
      .set(DEV_USER_HEADER, "viewer")
      .send({ slug: "nope", name: "Nope", permissions: ["issues.read"] });
    assert.equal(denied.status, 403);

    const typo = await request(off()).get("/api/principal").set(DEV_USER_HEADER, "vieweer");
    assert.equal(typo.status, 400, "an unknown dev user must fail loudly, not fall back to admin");
  });

  it("requires credentials in local mode", async () => {
    const denied = await request(local()).get("/api/principal");
    assert.equal(denied.status, 401);

    const login = await request(local())
      .post("/api/session")
      .send({ username: "admin", password: "admin" });
    assert.equal(login.status, 201);
    assert.equal(login.body.principal.username, "admin");
    const cookie = login.headers["set-cookie"] as unknown as string[];
    assert.ok(cookie);
    assert.ok(cookie[0].includes("HttpOnly"));

    const principal = await request(local()).get("/api/principal").set("Cookie", cookie);
    assert.equal(principal.status, 200);
    assert.equal(principal.body.kind, "user");
    assert.ok(principal.body.roles.includes("admin"));
  });

  it("rejects bad passwords", async () => {
    const bad = await request(local())
      .post("/api/session")
      .send({ username: "admin", password: "wrong" });
    assert.equal(bad.status, 401);
  });

  it("manages custom roles and user role assignment", async () => {
    const app = off();
    const created = await request(app)
      .post("/api/roles")
      .send({
        slug: "reviewer",
        name: "Reviewer",
        description: "PR review only",
        permissions: ["issues.read", "helix.read"],
      });
    assert.equal(created.status, 201);
    assert.equal(created.body.builtin, false);

    const user = await request(app)
      .post("/api/users")
      .send({
        username: "pat",
        displayName: "Pat",
        password: "pat-pass",
        roleSlugs: ["reviewer"],
      });
    assert.equal(user.status, 201);
    assert.deepEqual(user.body.roleSlugs, ["reviewer"]);

    const patched = await request(app)
      .patch(`/api/users/${user.body.id}`)
      .send({ roleSlugs: ["member", "reviewer"] });
    assert.equal(patched.status, 200);
    assert.deepEqual(patched.body.roleSlugs.sort(), ["member", "reviewer"]);

    const blocked = await request(app).delete(`/api/roles/${created.body.id}`);
    assert.equal(blocked.status, 400);

    await request(app).delete(`/api/users/${user.body.id}`).expect(204);
    await request(app).delete(`/api/roles/${created.body.id}`).expect(204);
  });

  it("refuses deleting a role a service token still depends on", async () => {
    const app = off();
    const role = await request(app)
      .post("/api/roles")
      .send({ slug: "bot-role", name: "Bot role", permissions: ["issues.write"] });
    const token = await request(app)
      .post("/api/tokens")
      .send({ name: "bound-bot", roleSlugs: ["bot-role"] });
    assert.equal(token.status, 201);

    const blocked = await request(app).delete(`/api/roles/${role.body.id}`);
    assert.equal(blocked.status, 400, "deleting it would silently strip the token's permissions");
    assert.match(blocked.body.error, /service tokens/);

    await request(app).delete(`/api/tokens/${token.body.id}`).expect(204);
    await request(app).delete(`/api/roles/${role.body.id}`).expect(204);
  });

  it("refuses deleting builtin roles", async () => {
    const roles = await request(off()).get("/api/roles");
    const admin = roles.body.find((role: { slug: string }) => role.slug === "admin");
    const result = await request(off()).delete(`/api/roles/${admin.id}`);
    assert.equal(result.status, 400);
  });

  it("rejects malformed permission strings", async () => {
    const result = await request(off())
      .post("/api/roles")
      .send({ slug: "bad", name: "Bad", permissions: ["not a permission"] });
    assert.equal(result.status, 400);
    assert.match(result.body.error, /Invalid permission/);
  });

  it("supports namespace wildcards in custom roles", async () => {
    const app = off();
    const role = await request(app)
      .post("/api/roles")
      .send({ slug: "prelude-lead", name: "Prelude lead", permissions: ["prelude.*"] });
    assert.equal(role.status, 201);

    const user = await request(app)
      .post("/api/users")
      .send({
        username: "lead",
        displayName: "Lead",
        password: "lead-pass",
        roleSlugs: ["prelude-lead", "viewer"],
      });
    assert.equal(user.status, 201);

    const cookie = await signIn("lead", "lead-pass");
    const principal = await request(local()).get("/api/principal").set("Cookie", cookie);
    assert.ok(principal.body.permissions.includes("prelude.*"));

    await request(app).delete(`/api/users/${user.body.id}`).expect(204);
    await request(app).delete(`/api/roles/${role.body.id}`).expect(204);
  });

  it("keeps the admin role permissions pinned so nobody can lock identity out", async () => {
    const roles = await request(off()).get("/api/roles");
    const admin = roles.body.find((role: { slug: string }) => role.slug === "admin");
    assert.equal(admin.permissionsLocked, true);

    const stripped = await request(off())
      .patch(`/api/roles/${admin.id}`)
      .send({ permissions: ["identity.read"] });
    assert.equal(stripped.status, 400);

    const renamed = await request(off())
      .patch(`/api/roles/${admin.id}`)
      .send({ name: "Suite admin", permissions: ["*"] });
    assert.equal(renamed.status, 200);
    assert.equal(renamed.body.name, "Suite admin");
  });

  it("refuses edits that would leave no active identity admin", async () => {
    const app = off();
    const users = await request(app).get("/api/users");
    const admin = users.body.find((user: { username: string }) => user.username === "admin");

    const demoted = await request(app)
      .patch(`/api/users/${admin.id}`)
      .send({ roleSlugs: ["viewer"] });
    assert.equal(demoted.status, 400);
    assert.match(demoted.body.error, /identity\.admin/);

    const disabled = await request(app).patch(`/api/users/${admin.id}`).send({ active: false });
    assert.equal(disabled.status, 400);

    const deleted = await request(app).delete(`/api/users/${admin.id}`);
    assert.equal(deleted.status, 400);

    // With a second admin present the same edits are allowed again.
    const spare = await request(app)
      .post("/api/users")
      .send({
        username: "admin2",
        displayName: "Spare admin",
        password: "admin2-pass",
        roleSlugs: ["admin"],
      });
    assert.equal(spare.status, 201);
    assert.equal((await request(app).patch(`/api/users/${admin.id}`).send({ active: false })).status, 200);
    assert.equal((await request(app).patch(`/api/users/${admin.id}`).send({ active: true })).status, 200);
    await request(app).delete(`/api/users/${spare.body.id}`).expect(204);
  });

  it("mints, resolves, and revokes service tokens in local mode", async () => {
    const cookie = await signIn("admin");
    const minted = await request(local())
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({ name: "helix-bot", roleSlugs: ["operator"] });
    assert.equal(minted.status, 201);
    assert.ok(minted.body.token?.startsWith("svc_"));
    assert.equal(minted.body.expiresAt, null);

    const principal = await request(local())
      .get("/api/principal")
      .set("Authorization", `Bearer ${minted.body.token}`);
    assert.equal(principal.status, 200);
    assert.equal(principal.body.kind, "service");
    assert.deepEqual(principal.body.roles, ["operator"]);

    const introspect = await request(local())
      .post("/api/introspect")
      .set("Authorization", `Bearer ${minted.body.token}`)
      .send({ token: minted.body.token });
    assert.equal(introspect.status, 200);
    assert.equal(introspect.body.active, true);

    await request(local())
      .delete(`/api/tokens/${minted.body.id}`)
      .set("Cookie", cookie)
      .expect(204);

    const revoked = await request(local())
      .get("/api/principal")
      .set("Authorization", `Bearer ${minted.body.token}`);
    assert.equal(revoked.status, 401);
  });

  it("treats expired service tokens as invalid", async () => {
    const cookie = await signIn("admin");
    const minted = await request(local())
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({ name: "short-lived", roleSlugs: ["viewer"], expiresInDays: 1 });
    assert.equal(minted.status, 201);
    assert.ok(minted.body.expiresAt > Date.now());

    // Move the expiry into the past without waiting a day.
    db.prepare(`UPDATE service_tokens SET expires_at = ? WHERE id = ?`).run(
      Date.now() - 1_000,
      minted.body.id,
    );
    const expired = await request(local())
      .get("/api/principal")
      .set("Authorization", `Bearer ${minted.body.token}`);
    assert.equal(expired.status, 401);

    const rejected = await request(local())
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({ name: "already-expired", roleSlugs: ["viewer"], expiresAt: Date.now() - 1 });
    assert.equal(rejected.status, 400);

    await request(local())
      .delete(`/api/tokens/${minted.body.id}`)
      .set("Cookie", cookie)
      .expect(204);
  });

  it("requires an authenticated caller to introspect tokens", async () => {
    const anonymous = await request(local()).post("/api/introspect").send({ token: "svc_whatever" });
    assert.equal(anonymous.status, 401);

    const cookie = await signIn("viewer");
    const unknown = await request(local())
      .post("/api/introspect")
      .set("Cookie", cookie)
      .send({ token: "svc_whatever" });
    assert.equal(unknown.status, 200);
    assert.equal(unknown.body.active, false);
  });

  it("forbids member from admin-only routes in local mode", async () => {
    const cookie = await signIn("member");
    const users = await request(local()).get("/api/users").set("Cookie", cookie);
    assert.equal(users.status, 200);

    const create = await request(local())
      .post("/api/users")
      .set("Cookie", cookie)
      .send({
        username: "nope",
        displayName: "Nope",
        password: "x",
        roleSlugs: ["viewer"],
      });
    assert.equal(create.status, 403);
  });

  it("revokes sessions on password change and supports self-service rotation", async () => {
    const app = local();
    const created = await request(off())
      .post("/api/users")
      .send({
        username: "rotate",
        displayName: "Rotate",
        password: "first-pass",
        roleSlugs: ["viewer"],
      });
    assert.equal(created.status, 201);

    const cookie = await signIn("rotate", "first-pass");
    assert.equal((await request(app).get("/api/principal").set("Cookie", cookie)).status, 200);

    const changed = await request(app)
      .post("/api/session/password")
      .set("Cookie", cookie)
      .send({ currentPassword: "first-pass", newPassword: "second-pass" });
    assert.equal(changed.status, 200);

    const stale = await request(app).get("/api/principal").set("Cookie", cookie);
    assert.equal(stale.status, 401, "changing a password must invalidate existing sessions");

    const reLogin = await signIn("rotate", "second-pass");
    assert.ok(reLogin);

    const wrongCurrent = await request(app)
      .post("/api/session/password")
      .set("Cookie", reLogin)
      .send({ currentPassword: "nope", newPassword: "third-pass" });
    assert.equal(wrongCurrent.status, 401);

    await request(off()).delete(`/api/users/${created.body.id}`).expect(204);
  });

  it("lets an admin revoke every session for a user", async () => {
    const created = await request(off())
      .post("/api/users")
      .send({
        username: "kickme",
        displayName: "Kick Me",
        password: "kick-pass",
        roleSlugs: ["viewer"],
      });
    const cookie = await signIn("kickme", "kick-pass");
    const before = await request(off()).get(`/api/users/${created.body.id}/sessions`);
    assert.equal(before.body.active, 1);

    const revoked = await request(off()).delete(`/api/users/${created.body.id}/sessions`);
    assert.equal(revoked.status, 200);
    assert.equal(revoked.body.revoked, 1);
    assert.equal((await request(local()).get("/api/principal").set("Cookie", cookie)).status, 401);

    await request(off()).delete(`/api/users/${created.body.id}`).expect(204);
  });

  it("answers unknown API paths with JSON, not the SPA shell", async () => {
    const missing = await request(off()).get("/api/nope");
    assert.equal(missing.status, 404);
    assert.match(missing.headers["content-type"], /application\/json/);
    assert.match(missing.body.error, /Unknown endpoint/);
  });

  it("answers malformed JSON bodies with a JSON error", async () => {
    const bad = await request(off())
      .post("/api/roles")
      .set("Content-Type", "application/json")
      .send("{not json");
    assert.equal(bad.status, 400);
    assert.match(bad.headers["content-type"], /application\/json/);
    assert.ok(bad.body.error);
  });

  it("never caches API responses", async () => {
    const principal = await request(off()).get("/api/principal");
    assert.equal(principal.headers["cache-control"], "no-store");
    assert.equal(principal.headers["x-content-type-options"], "nosniff");
  });

  it("exposes session cookie name and consumer helpers", () => {
    assert.equal(SESSION_COOKIE, "acme_identity_session");
    assert.equal(resolveConsumerAuthMode("off"), "off");
    assert.equal(localAdminFallback().roles[0], "admin");
  });
});

describe("cross-origin protection", () => {
  let dataDir: string;
  let db: ReturnType<typeof openDatabase>;

  before(() => {
    process.env.ACME_ALLOW_INSECURE = "1";
    dataDir = mkdtempSync(join(tmpdir(), "acme-identity-cors-"));
    db = openDatabase(dataDir);
  });

  after(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("blocks writes from another origin on the same host", async () => {
    // localhost:8318 and localhost:8316 are same-site, so SameSite=Lax alone
    // would still attach the session cookie to this request.
    const blocked = await request(createApp({ db, authMode: "off", http }))
      .post("/api/roles")
      .set("Origin", "http://localhost:8318")
      .send({ slug: "sneaky", name: "Sneaky", permissions: ["*"] });
    assert.equal(blocked.status, 403);
    assert.match(blocked.body.error, /Cross-origin/);
  });

  it("allows reads from another origin and writes from allowlisted ones", async () => {
    const app = createApp({
      db,
      authMode: "off",
      http: resolveHttpConfig({
        ACME_IDENTITY_ALLOWED_ORIGINS: "http://localhost:8318",
      } as NodeJS.ProcessEnv),
    });

    const read = await request(app).get("/api/principal").set("Origin", "http://localhost:8318");
    assert.equal(read.status, 200);
    assert.equal(read.headers["access-control-allow-origin"], "http://localhost:8318");
    assert.equal(read.headers["access-control-allow-credentials"], "true");

    const write = await request(app)
      .post("/api/roles")
      .set("Origin", "http://localhost:8318")
      .send({ slug: "trusted", name: "Trusted", permissions: ["issues.read"] });
    assert.equal(write.status, 201);
    await request(app).delete(`/api/roles/${write.body.id}`).expect(204);
  });

  it("allows same-origin and non-browser writes", async () => {
    const app = createApp({ db, authMode: "off", http });
    const noOrigin = await request(app)
      .post("/api/roles")
      .send({ slug: "curl-made", name: "Curl made", permissions: ["issues.read"] });
    assert.equal(noOrigin.status, 201);
    await request(app).delete(`/api/roles/${noOrigin.body.id}`).expect(204);
  });
});

describe("login throttling", () => {
  let dataDir: string;
  let db: ReturnType<typeof openDatabase>;

  before(() => {
    process.env.ACME_ALLOW_INSECURE = "1";
    dataDir = mkdtempSync(join(tmpdir(), "acme-identity-throttle-"));
    db = openDatabase(dataDir);
  });

  after(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("locks out repeated failures and still admits the right password afterwards", async () => {
    const app = createApp({ db, authMode: "local", http });
    for (let attempt = 0; attempt < 10; attempt++) {
      const response = await request(app)
        .post("/api/session")
        .send({ username: "admin", password: `wrong-${attempt}` });
      assert.equal(response.status, 401, `attempt ${attempt} should be a plain rejection`);
    }
    const throttled = await request(app)
      .post("/api/session")
      .send({ username: "admin", password: "admin" });
    assert.equal(throttled.status, 429);
    assert.ok(throttled.headers["retry-after"]);

    // A fresh app instance stands in for the lockout window elapsing.
    const later = await request(createApp({ db, authMode: "local", http }))
      .post("/api/session")
      .send({ username: "admin", password: "admin" });
    assert.equal(later.status, 201);
  });
});

describe("session lifecycle", () => {
  let dataDir: string;
  let db: ReturnType<typeof openDatabase>;

  before(() => {
    process.env.ACME_ALLOW_INSECURE = "1";
    dataDir = mkdtempSync(join(tmpdir(), "acme-identity-sessions-"));
    db = openDatabase(dataDir);
  });

  beforeEach(() => {
    db.prepare(`DELETE FROM sessions`).run();
  });

  after(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("rejects and reaps expired sessions", async () => {
    const app = createApp({ db, authMode: "local", http });
    const login = await request(app).post("/api/session").send({ username: "admin", password: "admin" });
    const cookie = login.headers["set-cookie"] as unknown as string[];
    db.prepare(`UPDATE sessions SET expires_at = ?`).run(Date.now() - 1_000);

    const expired = await request(app).get("/api/principal").set("Cookie", cookie);
    assert.equal(expired.status, 401);
    const remaining = db.prepare(`SELECT COUNT(*) AS n FROM sessions`).get() as { n: number };
    assert.equal(remaining.n, 0, "an expired session should be reaped on use");
  });

  it("signs out by clearing the cookie and deleting the session", async () => {
    const app = createApp({ db, authMode: "local", http });
    const login = await request(app).post("/api/session").send({ username: "admin", password: "admin" });
    const cookie = login.headers["set-cookie"] as unknown as string[];

    const signedOut = await request(app).delete("/api/session").set("Cookie", cookie);
    assert.equal(signedOut.status, 200);
    assert.match((signedOut.headers["set-cookie"] as unknown as string[])[0], /Max-Age=0/);
    assert.equal((await request(app).get("/api/principal").set("Cookie", cookie)).status, 401);
  });
});
