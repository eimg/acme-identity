import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDatabase } from "../src/db.js";
import { hashPassword, hashToken, tokenPrefix, verifyToken } from "../src/passwords.js";
import { createServiceTokenRecord, findServiceToken } from "../src/store.js";

describe("service token resolution", () => {
  let dataDir: string;
  let db: ReturnType<typeof openDatabase>;

  before(() => {
    dataDir = mkdtempSync(join(tmpdir(), "acme-identity-tokens-"));
    db = openDatabase(dataDir);
  });

  after(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("resolves a token regardless of how many others exist", () => {
    const tokens: string[] = [];
    for (let i = 0; i < 25; i++) {
      tokens.push(
        createServiceTokenRecord(db, { name: `bot-${i}`, roleSlugs: ["operator"] }).token!,
      );
    }

    // Cost must not scale with the number of minted tokens: a per-row KDF pass
    // took over half a second at this size and blocked the event loop while doing it.
    const started = performance.now();
    for (const token of tokens) assert.ok(findServiceToken(db, token));
    assert.equal(findServiceToken(db, "svc_not-a-real-token"), undefined);
    const elapsed = performance.now() - started;
    assert.ok(elapsed < 250, `26 lookups took ${elapsed.toFixed(0)}ms`);
  });

  it("does not spend a KDF pass rejecting an unknown token", () => {
    const started = performance.now();
    for (let i = 0; i < 50; i++) assert.equal(findServiceToken(db, `svc_bogus-${i}`), undefined);
    const elapsed = performance.now() - started;
    assert.ok(elapsed < 250, `50 rejections took ${elapsed.toFixed(0)}ms`);
  });

  it("keeps last_used_at fresh without writing on every request", () => {
    const minted = createServiceTokenRecord(db, { name: "chatty", roleSlugs: ["viewer"] });
    assert.ok(findServiceToken(db, minted.token!));
    const first = lastUsedAt(db, minted.id);
    assert.ok(first != null);

    assert.ok(findServiceToken(db, minted.token!));
    assert.equal(lastUsedAt(db, minted.id), first, "a second immediate call should not rewrite");

    db.prepare(`UPDATE service_tokens SET last_used_at = ? WHERE id = ?`).run(
      Date.now() - 120_000,
      minted.id,
    );
    assert.ok(findServiceToken(db, minted.token!));
    assert.ok(lastUsedAt(db, minted.id)! > Date.now() - 5_000, "a stale timestamp should refresh");
  });

  it("still resolves salted tokens minted before deterministic digests", () => {
    const legacyToken = "svc_legacy-token-value";
    db.prepare(
      `INSERT INTO service_tokens (name, token_hash, token_prefix, role_slugs_json, created_at, last_used_at, expires_at)
       VALUES (?, ?, ?, ?, ?, NULL, NULL)`,
    ).run(
      "legacy-bot",
      hashPassword(legacyToken),
      tokenPrefix(legacyToken),
      JSON.stringify(["viewer"]),
      Date.now(),
    );
    const found = findServiceToken(db, legacyToken);
    assert.equal(found?.name, "legacy-bot");
    assert.deepEqual(found?.roleSlugs, ["viewer"]);
  });

  it("hashes tokens deterministically and compares them safely", () => {
    assert.equal(hashToken("svc_abc"), hashToken("svc_abc"));
    assert.notEqual(hashToken("svc_abc"), hashToken("svc_abd"));
    assert.ok(verifyToken("svc_abc", hashToken("svc_abc")));
    assert.ok(!verifyToken("svc_abd", hashToken("svc_abc")));
    assert.ok(!verifyToken("svc_abc", "garbage"));
  });
});

function lastUsedAt(db: ReturnType<typeof openDatabase>, id: number): number | null {
  const row = db.prepare(`SELECT last_used_at AS value FROM service_tokens WHERE id = ?`).get(id) as
    | { value: number | null }
    | undefined;
  return row?.value ?? null;
}
