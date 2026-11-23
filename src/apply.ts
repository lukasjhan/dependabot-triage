import { execFile, spawn } from "node:child_process";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import semver from "semver";
import { GitHub } from "./lib/github.ts";
import type { ApplyResult, Classification, Decision, PackageFacts } from "./lib/types.ts";

const exec = promisify(execFile);
const LOG_TAIL = 4_000;

type Options = {
  cwd: string;
  verify: string[];
  now?: Date;
  baseline?: Map<string, string[]>;
};

type Candidate = { decision: Decision; facts: PackageFacts };

export async function apply(gh: GitHub, classification: Classification, facts: PackageFacts[], opts: Options): Promise<ApplyResult> {
  const result: ApplyResult = { applied: [], deferred: [], skipped: [], failed: [], verify: [] };
  await assertClean(opts.cwd);

  const factsByName = new Map(facts.map((f) => [f.package, f]));
  const openPrs = await dependabotPrs(gh);
  const minAge = await minimumReleaseAge(opts.cwd);
  const now = opts.now ?? new Date();

  const candidates: Candidate[] = [];
  for (const decision of classification.packages) {
    if (decision.class !== "lockfile" && decision.class !== "override") continue;
    const f = factsByName.get(decision.package)!;
    const pr = openPrs.get(decision.package);
    if (pr) {
      result.skipped.push({ package: f.package, reason: "dependabot-pr", pr });
      continue;
    }
    if (decision.class === "override" && f.existingOverride) {
      result.failed.push({ package: f.package, reason: "existing-override", log: `pnpm.overrides already has ${f.package}: ${f.existingOverride}` });
      continue;
    }
    const availableAt = releaseAvailableAt(f, minAge);
    if (availableAt && availableAt > now) {
      result.deferred.push({ package: f.package, reason: "minimum-release-age", availableAt: availableAt.toISOString() });
      continue;
    }
    candidates.push({ decision, facts: f });
  }

  if (candidates.length === 0) return result;

  const baseline = new Map<string, string[]>();
  for (const c of candidates) baseline.set(c.facts.package, await installedVersions(opts.cwd, c.facts.package));
  opts = { ...opts, baseline };

  const together = await attempt(candidates, opts);
  if (together.ok) {
    result.applied.push(...together.applied);
    result.verify = together.verify;
    return result;
  }

  const passing: Candidate[] = [];
  for (const c of candidates) {
    const single = await attempt([c], opts);
    if (single.ok) passing.push(c);
    else result.failed.push({ package: c.facts.package, reason: single.reason, log: single.log });
  }

  if (passing.length === 0) {
    await reset(opts.cwd);
  } else {
    const final = await attempt(passing, opts);
    if (final.ok) {
      result.applied.push(...final.applied);
      result.verify = final.verify;
    } else {
      for (const c of passing) result.failed.push({ package: c.facts.package, reason: final.reason, log: final.log });
      await reset(opts.cwd);
    }
  }
  return result;
}

type Attempt =
  | { ok: true; applied: ApplyResult["applied"]; verify: ApplyResult["verify"] }
  | { ok: false; reason: "install-failed" | "not-resolved" | "verify-failed"; log: string };

async function attempt(candidates: Candidate[], opts: Options): Promise<Attempt> {
  await reset(opts.cwd);

  const overrides = candidates.filter((c) => c.decision.class === "override");
  if (overrides.length > 0) await addOverrides(opts.cwd, overrides.map((c) => c.facts));

  const lockfile = candidates.filter((c) => c.decision.class === "lockfile").map((c) => c.facts.package);
  const install = lockfile.length > 0
    ? await sh(opts.cwd, "pnpm", ["update", "--no-save", ...lockfile])
    : await sh(opts.cwd, "pnpm", ["install", "--no-frozen-lockfile"]);
  if (install.code !== 0) return { ok: false, reason: "install-failed", log: install.log };
  if (overrides.length > 0 && lockfile.length > 0) {
    const again = await sh(opts.cwd, "pnpm", ["install", "--no-frozen-lockfile"]);
    if (again.code !== 0) return { ok: false, reason: "install-failed", log: again.log };
  }

  const applied: ApplyResult["applied"] = [];
  for (const c of candidates) {
    const versions = await installedVersions(opts.cwd, c.facts.package);
    const still = versions.filter((v) => c.facts.vulnerableRanges.some((r) => semver.satisfies(v, r)));
    if (still.length > 0) {
      return { ok: false, reason: "not-resolved", log: `${c.facts.package} still resolves to vulnerable ${still.join(", ")}` };
    }
    const untouched = new Set((opts.baseline?.get(c.facts.package) ?? []).filter((v) => !c.facts.installed.includes(v)));
    applied.push({
      package: c.facts.package,
      method: c.decision.class as "lockfile" | "override",
      from: c.facts.installed,
      to: versions.filter((v) => !untouched.has(v)).sort(semver.compare),
    });
  }

  const verify: ApplyResult["verify"] = [];
  for (const command of opts.verify) {
    const run = await sh(opts.cwd, "sh", ["-c", command]);
    verify.push({ command, ok: run.code === 0 });
    if (run.code !== 0) return { ok: false, reason: "verify-failed", log: `$ ${command}\n${run.log}` };
  }
  return { ok: true, applied, verify };
}

async function addOverrides(cwd: string, facts: PackageFacts[]): Promise<void> {
  const path = join(cwd, "package.json");
  const raw = await readFile(path, "utf8");
  const manifest = JSON.parse(raw);
  manifest.pnpm ??= {};
  manifest.pnpm.overrides ??= {};
  for (const f of facts) manifest.pnpm.overrides[`${f.package}@<${f.targetVersion}`] = `^${f.targetVersion}`;
  const indent = raw.match(/^[ \t]+/m)?.[0] ?? "  ";
  await writeFile(path, `${JSON.stringify(manifest, null, indent)}\n`);
}

async function installedVersions(cwd: string, name: string): Promise<string[]> {
  const { stdout } = await exec("pnpm", ["why", name, "-r", "--json"], { cwd, maxBuffer: 64 * 1024 * 1024 });
  const versions = new Set<string>();
  const walk = (node: Record<string, unknown>) => {
    for (const key of ["dependencies", "devDependencies", "optionalDependencies"]) {
      for (const [n, child] of Object.entries((node[key] ?? {}) as Record<string, Record<string, unknown>>)) {
        if (n === name) versions.add(child.version as string);
        else walk(child);
      }
    }
  };
  for (const importer of JSON.parse(stdout || "[]")) walk(importer);
  return [...versions];
}

async function dependabotPrs(gh: GitHub): Promise<Map<string, number>> {
  const pulls = await gh.paginate<{ number: number; title: string; user: { login: string } }>(`${gh.repoPath}/pulls?state=open&per_page=100`);
  const map = new Map<string, number>();
  for (const p of pulls) {
    if (p.user.login !== "dependabot[bot]") continue;
    const name = p.title.match(/\bbump (\S+) from\b/i)?.[1];
    if (name) map.set(name, p.number);
  }
  return map;
}

async function minimumReleaseAge(cwd: string): Promise<number> {
  const { stdout } = await exec("pnpm", ["config", "get", "minimum-release-age"], { cwd });
  const minutes = Number(stdout.trim());
  return Number.isFinite(minutes) ? minutes : 0;
}

function releaseAvailableAt(f: PackageFacts, minutes: number): Date | null {
  if (!minutes || !f.targetPublishedAt) return null;
  return new Date(new Date(f.targetPublishedAt).getTime() + minutes * 60_000);
}

async function assertClean(cwd: string): Promise<void> {
  const { stdout } = await exec("git", ["status", "--porcelain", "--", "package.json", "pnpm-lock.yaml"], { cwd });
  if (stdout.trim()) throw new Error("package.json or pnpm-lock.yaml has uncommitted changes");
}

async function reset(cwd: string): Promise<void> {
  await exec("git", ["checkout", "--", "package.json", "pnpm-lock.yaml"], { cwd });
}

function sh(cwd: string, cmd: string, args: string[]): Promise<{ code: number; log: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
    let log = "";
    child.stdout.on("data", (c) => (log += c));
    child.stderr.on("data", (c) => (log += c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, log: log.slice(-LOG_TAIL) }));
  });
}

if (import.meta.main) {
  const [classPath = "out/classification.json", factsPath = "out/facts.json", output = "out/apply.json", cwd = process.cwd()] =
    process.argv.slice(2);
  const classification = JSON.parse(await readFile(classPath, "utf8")) as Classification;
  const facts = JSON.parse(await readFile(factsPath, "utf8")) as PackageFacts[];
  const verify = (process.env.TRIAGE_VERIFY ?? "").split("\n").map((s) => s.trim()).filter(Boolean);
  const result = await apply(GitHub.fromEnv(), classification, facts, { cwd, verify });
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, JSON.stringify(result, null, 2));
  console.log(
    `applied ${result.applied.length}, deferred ${result.deferred.length}, skipped ${result.skipped.length}, failed ${result.failed.length} -> ${output}`,
  );
}
