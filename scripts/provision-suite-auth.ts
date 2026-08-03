import { chmodSync, existsSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { openDatabase } from "../src/db.js";
import {
  createRole,
  createServiceTokenRecord,
  deleteServiceToken,
  getRoleBySlug,
  listServiceTokens,
  updateRole,
} from "../src/store.js";

const identityRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const suiteRoot = resolve(identityRoot, "..");
const validityDays = Number(process.env.ACME_SERVICE_TOKEN_DAYS ?? 90);
if (!Number.isInteger(validityDays) || validityDays < 1 || validityDays > 365) {
  throw new Error("ACME_SERVICE_TOKEN_DAYS must be an integer from 1 to 365");
}

const roleSpecs = [
  { slug: "svc-projects-to-issues", name: "Projects to Issues", permissions: ["issues.write"] },
  { slug: "svc-issues-to-helix", name: "Issues to Helix", permissions: ["helix.trigger", "helix.review"] },
  { slug: "svc-issues-to-projects", name: "Issues to Projects", permissions: ["projects.write"] },
  { slug: "svc-helix-to-issues", name: "Helix to Issues", permissions: ["issues.write"] },
  { slug: "svc-helix-to-prelude", name: "Helix to Prelude", permissions: ["prelude.read"] },
  { slug: "svc-obs-to-prelude", name: "Observability to Prelude", permissions: ["prelude.read"] },
  { slug: "svc-obs-to-issues", name: "Observability to Issues", permissions: ["issues.read"] },
  { slug: "svc-obs-to-projects", name: "Observability to Projects", permissions: ["projects.read"] },
  { slug: "svc-obs-to-helix", name: "Observability to Helix", permissions: ["helix.read"] },
  { slug: "svc-prelude-to-steering", name: "Prelude to Steering", permissions: ["steering.notify.prelude"] },
  { slug: "svc-helix-to-steering", name: "Helix to Steering", permissions: ["steering.notify.helix"] },
  { slug: "svc-issues-to-steering", name: "Issues to Steering", permissions: ["steering.notify.issues"] },
  { slug: "svc-projects-to-steering", name: "Projects to Steering", permissions: ["steering.notify.projects"] },
  { slug: "svc-steering-to-prelude", name: "Steering to Prelude", permissions: ["prelude.steering.export"] },
  { slug: "svc-steering-to-helix", name: "Steering to Helix", permissions: ["helix.steering.recover"] },
  { slug: "svc-steering-to-issues", name: "Steering to Issues", permissions: ["issues.steering.trigger"] },
  { slug: "svc-steering-to-projects", name: "Steering to Projects", permissions: ["projects.steering.submit"] },
] as const;

const edgeSpecs = [
  {
    name: "projects-to-issues",
    role: "svc-projects-to-issues",
    file: resolve(suiteRoot, "acme-projects/.env"),
    key: "ACME_ISSUES_TOKEN",
    extras: { ACME_TRUSTED_ISSUES_ORIGINS: "http://127.0.0.1:8320" },
  },
  {
    name: "issues-to-helix",
    role: "svc-issues-to-helix",
    file: resolve(suiteRoot, "acme-issues/.env"),
    key: "ACME_HELIX_TOKEN",
    extras: { ACME_TRUSTED_HELIX_ORIGINS: "http://127.0.0.1:8319" },
  },
  {
    name: "issues-to-projects",
    role: "svc-issues-to-projects",
    file: resolve(suiteRoot, "acme-issues/.env"),
    key: "ACME_PROJECTS_TOKEN",
    extras: { ACME_TRUSTED_PROJECTS_ORIGINS: "http://127.0.0.1:8321" },
  },
  {
    name: "helix-to-issues",
    role: "svc-helix-to-issues",
    file: resolve(suiteRoot, "acme-todo/.helix/.env"),
    key: "HELIX_ISSUES_TOKEN",
    extras: { HELIX_TRUSTED_ISSUES_ORIGINS: "http://127.0.0.1:8320" },
  },
  {
    name: "helix-to-prelude",
    role: "svc-helix-to-prelude",
    file: resolve(suiteRoot, "acme-todo/.helix/.env"),
    key: "HELIX_PRELUDE_TOKEN",
    extras: { HELIX_TRUSTED_PRELUDE_ORIGINS: "http://127.0.0.1:8318" },
  },
  {
    name: "obs-to-prelude",
    role: "svc-obs-to-prelude",
    file: resolve(suiteRoot, "acme-obs/.env"),
    key: "ACME_OBS_PRELUDE_TOKEN",
    extras: {},
  },
  {
    name: "obs-to-issues",
    role: "svc-obs-to-issues",
    file: resolve(suiteRoot, "acme-obs/.env"),
    key: "ACME_OBS_ISSUES_TOKEN",
    extras: {},
  },
  {
    name: "obs-to-projects",
    role: "svc-obs-to-projects",
    file: resolve(suiteRoot, "acme-obs/.env"),
    key: "ACME_OBS_PROJECTS_TOKEN",
    extras: {},
  },
  {
    name: "obs-to-helix",
    role: "svc-obs-to-helix",
    file: resolve(suiteRoot, "acme-obs/.env"),
    key: "ACME_OBS_HELIX_TOKEN",
    extras: {},
  },
  {
    name: "prelude-to-steering",
    role: "svc-prelude-to-steering",
    file: resolve(suiteRoot, "prelude/.env"),
    key: "ACME_STEERING_TOKEN",
    extras: { ACME_STEERING_URL: "http://127.0.0.1:8323", ACME_TRUSTED_STEERING_ORIGINS: "http://127.0.0.1:8323" },
  },
  {
    name: "helix-to-steering",
    role: "svc-helix-to-steering",
    file: resolve(suiteRoot, "acme-todo/.helix/.env"),
    key: "ACME_STEERING_TOKEN",
    extras: { ACME_STEERING_URL: "http://127.0.0.1:8323", ACME_TRUSTED_STEERING_ORIGINS: "http://127.0.0.1:8323" },
  },
  {
    name: "issues-to-steering",
    role: "svc-issues-to-steering",
    file: resolve(suiteRoot, "acme-issues/.env"),
    key: "ACME_STEERING_TOKEN",
    extras: { ACME_STEERING_URL: "http://127.0.0.1:8323", ACME_TRUSTED_STEERING_ORIGINS: "http://127.0.0.1:8323" },
  },
  {
    name: "projects-to-steering",
    role: "svc-projects-to-steering",
    file: resolve(suiteRoot, "acme-projects/.env"),
    key: "ACME_STEERING_TOKEN",
    extras: { ACME_STEERING_URL: "http://127.0.0.1:8323", ACME_TRUSTED_STEERING_ORIGINS: "http://127.0.0.1:8323" },
  },
  {
    name: "steering-to-prelude",
    role: "svc-steering-to-prelude",
    file: resolve(suiteRoot, "acme-steering/.env"),
    key: "ACME_STEERING_PRELUDE_TOKEN",
    extras: { ACME_STEERING_PRELUDE_URL: "http://127.0.0.1:8318", ACME_STEERING_TRUSTED_PRELUDE_ORIGINS: "http://127.0.0.1:8318" },
  },
  {
    name: "steering-to-helix",
    role: "svc-steering-to-helix",
    file: resolve(suiteRoot, "acme-steering/.env"),
    key: "ACME_STEERING_HELIX_TOKEN",
    extras: { ACME_STEERING_HELIX_URL: "http://127.0.0.1:8319", ACME_STEERING_TRUSTED_HELIX_ORIGINS: "http://127.0.0.1:8319" },
  },
  {
    name: "steering-to-issues",
    role: "svc-steering-to-issues",
    file: resolve(suiteRoot, "acme-steering/.env"),
    key: "ACME_STEERING_ISSUES_TOKEN",
    extras: { ACME_STEERING_ISSUES_URL: "http://127.0.0.1:8320", ACME_STEERING_TRUSTED_ISSUES_ORIGINS: "http://127.0.0.1:8320" },
  },
  {
    name: "steering-to-projects",
    role: "svc-steering-to-projects",
    file: resolve(suiteRoot, "acme-steering/.env"),
    key: "ACME_STEERING_PROJECTS_TOKEN",
    extras: { ACME_STEERING_PROJECTS_URL: "http://127.0.0.1:8321", ACME_STEERING_TRUSTED_PROJECTS_ORIGINS: "http://127.0.0.1:8321" },
  },
] as const;

const staticEnvSpecs = [
  {
    file: resolve(suiteRoot, "prelude/.env"),
    values: { PRELUDE_TRUSTED_PRIMER_ORIGINS: "http://127.0.0.1:8317" },
  },
] as const;

const db = openDatabase();
const originals = new Map<string, { content: string; mode: number }>();
const createdTokenIds: number[] = [];

try {
  for (const spec of roleSpecs) {
    const current = getRoleBySlug(db, spec.slug);
    const description = `Least-privilege service role for ${spec.name}`;
    if (current) {
      updateRole(db, current.id, { name: spec.name, description, permissions: [...spec.permissions] });
    } else {
      createRole(db, { slug: spec.slug, name: spec.name, description, permissions: [...spec.permissions] });
    }
  }

  const expiresAt = Date.now() + validityDays * 24 * 60 * 60 * 1000;
  const minted = edgeSpecs.map((edge) => {
    const token = createServiceTokenRecord(db, {
      name: edge.name,
      roleSlugs: [edge.role],
      expiresAt,
    });
    createdTokenIds.push(token.id);
    return { edge, token };
  });

  for (const { edge, token } of minted) {
    ensureEnvFile(edge.file);
    if (!originals.has(edge.file)) {
      const stat = statSync(edge.file);
      originals.set(edge.file, { content: readFileSync(edge.file, "utf8"), mode: stat.mode });
    }
    updateEnvFile(edge.file, { [edge.key]: token.token!, ...edge.extras });
  }
  for (const spec of staticEnvSpecs) {
    ensureEnvFile(spec.file);
    if (!originals.has(spec.file)) {
      const stat = statSync(spec.file);
      originals.set(spec.file, { content: readFileSync(spec.file, "utf8"), mode: stat.mode });
    }
    updateEnvFile(spec.file, spec.values);
  }

  const newIds = new Set(createdTokenIds);
  for (const token of listServiceTokens(db)) {
    if (edgeSpecs.some((edge) => edge.name === token.name) && !newIds.has(token.id)) {
      deleteServiceToken(db, token.id);
    }
  }

  console.log(`Provisioned ${edgeSpecs.length} scoped service tokens; expires ${new Date(expiresAt).toISOString()}.`);
} catch (error) {
  for (const [file, original] of originals) {
    writeFileSync(file, original.content, { mode: original.mode });
    chmodSync(file, original.mode);
  }
  for (const id of createdTokenIds) deleteServiceToken(db, id);
  throw error;
} finally {
  db.close();
}

function updateEnvFile(file: string, values: Record<string, string>): void {
  let content = readFileSync(file, "utf8");
  for (const [key, value] of Object.entries(values)) {
    const pattern = new RegExp(`^${key}=.*$`, "m");
    content = pattern.test(content)
      ? content.replace(pattern, `${key}=${value}`)
      : `${content.replace(/\s*$/, "")}\n${key}=${value}\n`;
  }
  const temporary = `${file}.provisioning`;
  writeFileSync(temporary, content, { mode: 0o600 });
  chmodSync(temporary, 0o600);
  renameSync(temporary, file);
  chmodSync(file, 0o600);
}

function ensureEnvFile(file: string): void {
  if (existsSync(file)) return;
  const example = `${file}.example`;
  if (!existsSync(example)) throw new Error(`Missing environment template: ${example}`);
  writeFileSync(file, readFileSync(example, "utf8"), { mode: 0o600 });
  chmodSync(file, 0o600);
}
