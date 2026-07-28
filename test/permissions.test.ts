import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  grants,
  hasAllPermissions,
  hasAnyPermission,
  hasPermission,
  hasRole,
  isSuiteAdmin,
  isValidPermission,
} from "../src/permissions.js";

const holder = (permissions: string[], roles: string[] = []) => ({ permissions, roles });

describe("permission matching", () => {
  it("matches exact grants", () => {
    assert.equal(grants("prelude.write", "prelude.write"), true);
    assert.equal(grants("prelude.write", "prelude.read"), false);
  });

  it("treats * as everything", () => {
    assert.equal(hasPermission(holder(["*"]), "anything.at.all"), true);
    assert.equal(isSuiteAdmin(holder(["*"])), true);
    assert.equal(isSuiteAdmin(holder(["identity.admin"])), false);
  });

  it("expands namespace wildcards without crossing namespaces", () => {
    const lead = holder(["prelude.*"]);
    assert.equal(hasPermission(lead, "prelude.write"), true);
    assert.equal(hasPermission(lead, "prelude.export"), true);
    assert.equal(hasPermission(lead, "preludex.write"), false);
    assert.equal(hasPermission(lead, "issues.write"), false);
  });

  it("supports nested product keys", () => {
    assert.equal(hasPermission(holder(["primer.*"]), "primer.evidence.read"), true);
    assert.equal(hasPermission(holder(["primer.evidence.*"]), "primer.evidence.read"), true);
    assert.equal(hasPermission(holder(["primer.evidence.*"]), "primer.ask"), false);
  });

  it("is case and whitespace tolerant on the requested key", () => {
    assert.equal(hasPermission(holder(["issues.write"]), " Issues.Write "), true);
  });

  it("offers any/all combinators", () => {
    const member = holder(["issues.write", "projects.write"]);
    assert.equal(hasAnyPermission(member, ["helix.merge", "issues.write"]), true);
    assert.equal(hasAllPermissions(member, ["helix.merge", "issues.write"]), false);
    assert.equal(hasAllPermissions(member, ["issues.write", "projects.write"]), true);
  });

  it("keeps role checks literal so they never disagree with permission checks", () => {
    const admin = holder(["*"], ["admin"]);
    assert.equal(hasRole(admin, "admin"), true);
    assert.equal(hasRole(admin, "operator"), false);
    assert.equal(hasPermission(admin, "helix.merge"), true);
  });

  it("validates the shape of permission strings", () => {
    for (const good of ["*", "identity.read", "prelude.*", "primer.evidence.read", "acme-issues.write"]) {
      assert.equal(isValidPermission(good), true, `${good} should be valid`);
    }
    for (const bad of ["", "identity", "identity read", "*.read", ".read", "identity.", "a b.c"]) {
      assert.equal(isValidPermission(bad), false, `${bad} should be invalid`);
    }
  });
});
