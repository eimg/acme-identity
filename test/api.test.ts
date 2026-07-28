import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { createApp } from "../src/app.js";
import { openDatabase } from "../src/db.js";
import { localAdminFallback, resolveConsumerAuthMode } from "../src/client.js";
import { SESSION_COOKIE } from "../src/types.js";

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

  it("seeds builtin roles and users", async () => {
    const app = createApp({ db, authMode: "off" });
    const roles = await request(app).get("/api/roles");
    assert.equal(roles.status, 200);
    assert.deepEqual(
      roles.body.map((role: { slug: string }) => role.slug).sort(),
      ["admin", "member", "operator", "viewer"],
    );

    const users = await request(app).get("/api/users");
    assert.equal(users.status, 200);
    assert.equal(users.body.length, 4);
  });

  it("resolves anonymous callers as admin when mode=off", async () => {
    const app = createApp({ db, authMode: "off" });
    const principal = await request(app).get("/api/principal");
    assert.equal(principal.status, 200);
    assert.equal(principal.body.kind, "dev");
    assert.deepEqual(principal.body.roles, ["admin"]);
    assert.ok(principal.body.permissions.includes("*"));
  });

  it("requires credentials in local mode", async () => {
    const app = createApp({ db, authMode: "local" });
    const denied = await request(app).get("/api/principal");
    assert.equal(denied.status, 401);

    const login = await request(app)
      .post("/api/session")
      .send({ username: "admin", password: "admin" });
    assert.equal(login.status, 201);
    assert.equal(login.body.principal.username, "admin");
    const cookie = login.headers["set-cookie"];
    assert.ok(cookie);

    const principal = await request(app).get("/api/principal").set("Cookie", cookie);
    assert.equal(principal.status, 200);
    assert.equal(principal.body.kind, "user");
    assert.ok(principal.body.roles.includes("admin"));
  });

  it("rejects bad passwords", async () => {
    const app = createApp({ db, authMode: "local" });
    const bad = await request(app)
      .post("/api/session")
      .send({ username: "admin", password: "wrong" });
    assert.equal(bad.status, 401);
  });

  it("manages custom roles and user role assignment", async () => {
    const app = createApp({ db, authMode: "off" });
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

  it("refuses deleting builtin roles", async () => {
    const app = createApp({ db, authMode: "off" });
    const roles = await request(app).get("/api/roles");
    const admin = roles.body.find((role: { slug: string }) => role.slug === "admin");
    const result = await request(app).delete(`/api/roles/${admin.id}`);
    assert.equal(result.status, 400);
  });

  it("mints and introspects service tokens in local mode", async () => {
    const app = createApp({ db, authMode: "local" });
    const login = await request(app)
      .post("/api/session")
      .send({ username: "admin", password: "admin" });
    const cookie = login.headers["set-cookie"];

    const minted = await request(app)
      .post("/api/tokens")
      .set("Cookie", cookie)
      .send({ name: "helix-bot", roleSlugs: ["operator"] });
    assert.equal(minted.status, 201);
    assert.ok(minted.body.token?.startsWith("svc_"));

    const principal = await request(app)
      .get("/api/principal")
      .set("Authorization", `Bearer ${minted.body.token}`);
    assert.equal(principal.status, 200);
    assert.equal(principal.body.kind, "service");
    assert.deepEqual(principal.body.roles, ["operator"]);

    const introspect = await request(app)
      .post("/api/introspect")
      .send({ token: minted.body.token });
    assert.equal(introspect.status, 200);
    assert.equal(introspect.body.active, true);

    await request(app)
      .delete(`/api/tokens/${minted.body.id}`)
      .set("Cookie", cookie)
      .expect(204);

    const after = await request(app)
      .get("/api/principal")
      .set("Authorization", `Bearer ${minted.body.token}`);
    assert.equal(after.status, 401);
  });

  it("forbids member from admin-only routes in local mode", async () => {
    const app = createApp({ db, authMode: "local" });
    const login = await request(app)
      .post("/api/session")
      .send({ username: "member", password: "member" });
    const cookie = login.headers["set-cookie"];

    const users = await request(app).get("/api/users").set("Cookie", cookie);
    assert.equal(users.status, 200);

    const create = await request(app)
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

  it("exposes session cookie name and consumer helpers", () => {
    assert.equal(SESSION_COOKIE, "acme_identity_session");
    assert.equal(resolveConsumerAuthMode("off"), "off");
    assert.equal(localAdminFallback().roles[0], "admin");
  });
});
