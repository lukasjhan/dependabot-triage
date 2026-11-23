import { execFile } from "node:child_process";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import semver from "semver";
import type { Alert, ClassHint, DirectDep, Edge, PackageFacts } from "./lib/types.ts";

const exec = promisify(execFile);

type WhyNode = {
  name?: string;
  from?: string;
  version: string;
  path: string;
  dependencies?: Record<string, WhyNode>;
  devDependencies?: Record<string, WhyNode>;
  optionalDependencies?: Record<string, WhyNode>;
};

type Manifest = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  pnpm?: { overrides?: Record<string, string> };
};

export async function facts(alerts: Alert[], cwd: string): Promise<PackageFacts[]> {
  const root = await readManifest(cwd);
  const groups = Map.groupBy(alerts, (a) => a.package);
  const result: PackageFacts[] = [];
  for (const [name, group] of groups) {
    result.push(await packageFacts(name, group, cwd, root));
  }
  return result;
}

async function packageFacts(name: string, alerts: Alert[], cwd: string, root: Manifest): Promise<PackageFacts> {
  const patched = alerts.map((a) => a.patchedVersion);
  const targetVersion = patched.includes(null) ? null : semver.rsort(patched as string[])[0];

  const all = await why(name, cwd, false);
  const prod = await why(name, cwd, true);
  const edges = await collectEdges(name, all, targetVersion);
  const installed = [...new Set(edges.map((e) => e.childVersion))].sort(semver.compare);
  const directVia = [...new Set(edges.map((e) => e.via))];

  return {
    package: name,
    alerts: alerts.map((a) => a.number),
    severity: maxSeverity(alerts),
    malware: alerts.some((a) => a.advisoryType === "malware"),
    targetVersion,
    targetPublishedAt: targetVersion ? await publishedAt(name, targetVersion) : null,
    installed,
    prodReachable: prod.some((n) => findsPackage(n, name)),
    existingOverride: root.pnpm?.overrides?.[name] ?? null,
    directVia: await Promise.all(directVia.map((d) => directDep(d, root))),
    edges,
    hint: hint(targetVersion, installed, edges),
  };
}

async function why(name: string, cwd: string, prodOnly: boolean): Promise<WhyNode[]> {
  const args = ["why", name, "-r", "--json", ...(prodOnly ? ["--prod"] : [])];
  const { stdout } = await exec("pnpm", args, { cwd, maxBuffer: 64 * 1024 * 1024 });
  return stdout.trim() ? (JSON.parse(stdout) as WhyNode[]) : [];
}

async function collectEdges(name: string, importers: WhyNode[], target: string | null): Promise<Edge[]> {
  const seen = new Map<string, Edge>();

  async function walk(node: WhyNode, parent: string | null, via: string | null): Promise<void> {
    const label = parent ? `${parent}@${node.version}` : `${node.name ?? "."} (root)`;
    for (const [childName, child] of children(node)) {
      if (childName !== name) {
        await walk(child, childName, via ?? childName);
        continue;
      }
      const key = `${label}>${child.version}`;
      if (seen.has(key)) continue;
      const range = declaredRange(await readManifest(node.path), name);
      const satisfies = target && range ? semver.satisfies(target, range) : null;
      seen.set(key, {
        parent: label,
        declaredRange: range,
        childVersion: child.version,
        via: via ?? childName,
        targetSatisfies: satisfies,
        parentFixVersion:
          parent && target && satisfies === false ? await parentFixVersion(parent, node.version, name, target) : null,
      });
    }
  }

  for (const importer of importers) {
    await walk(importer, null, null);
  }
  return [...seen.values()];
}

async function parentFixVersion(parent: string, current: string, child: string, target: string): Promise<string | null> {
  const { versions } = await packument(parent);
  const candidates = Object.keys(versions)
    .filter((v) => !semver.prerelease(v) && semver.gt(v, current))
    .sort(semver.compare);
  for (const v of candidates) {
    const range = declaredRange(versions[v], child);
    if (range && semver.satisfies(target, range)) return v;
  }
  return null;
}

function children(node: WhyNode): [string, WhyNode][] {
  return [
    ...Object.entries(node.dependencies ?? {}),
    ...Object.entries(node.devDependencies ?? {}),
    ...Object.entries(node.optionalDependencies ?? {}),
  ];
}

function findsPackage(node: WhyNode, name: string): boolean {
  return children(node).some(([n, c]) => n === name || findsPackage(c, name));
}

function declaredRange(manifest: Manifest, name: string): string | null {
  return (
    manifest.dependencies?.[name] ??
    manifest.optionalDependencies?.[name] ??
    manifest.devDependencies?.[name] ??
    manifest.peerDependencies?.[name] ??
    null
  );
}

async function directDep(name: string, root: Manifest): Promise<DirectDep> {
  const dev = root.devDependencies?.[name];
  return {
    name,
    declaredRange: root.dependencies?.[name] ?? root.optionalDependencies?.[name] ?? dev ?? null,
    dev: dev !== undefined,
    latest: await latestVersion(name),
  };
}

function hint(target: string | null, installed: string[], edges: Edge[]): ClassHint {
  if (!target) return "no-fix";
  if (installed.length > 0 && installed.every((v) => semver.gte(v, target))) return "already-fixed";
  if (edges.every((e) => e.targetSatisfies === true)) return "lockfile";
  const breaking = installed.some((v) => {
    if (semver.major(v) !== semver.major(target)) return true;
    return semver.major(target) === 0 && semver.minor(v) !== semver.minor(target);
  });
  return breaking ? "breaking" : "override";
}

const SEVERITY = ["low", "medium", "high", "critical"] as const;

function maxSeverity(alerts: Alert[]): Alert["severity"] {
  return alerts.reduce((m, a) => (SEVERITY.indexOf(a.severity) > SEVERITY.indexOf(m) ? a.severity : m), "low" as Alert["severity"]);
}

async function readManifest(dir: string): Promise<Manifest> {
  return JSON.parse(await readFile(join(dir, "package.json"), "utf8")) as Manifest;
}

type Packument = {
  "dist-tags": { latest: string };
  time: Record<string, string>;
  versions: Record<string, Manifest>;
};

const registry = new Map<string, Promise<Packument>>();

function packument(name: string): Promise<Packument> {
  if (!registry.has(name)) {
    registry.set(
      name,
      fetch(`https://registry.npmjs.org/${name.replace("/", "%2F")}`).then((r) => {
        if (!r.ok) throw new Error(`registry ${name} -> ${r.status}`);
        return r.json();
      }),
    );
  }
  return registry.get(name)!;
}

async function publishedAt(name: string, version: string): Promise<string | null> {
  return (await packument(name)).time[version] ?? null;
}

async function latestVersion(name: string): Promise<string> {
  return (await packument(name))["dist-tags"].latest;
}

if (import.meta.main) {
  const [input = "out/alerts.json", output = "out/facts.json", cwd = process.cwd()] = process.argv.slice(2);
  const alerts = JSON.parse(await readFile(input, "utf8")) as Alert[];
  const result = await facts(alerts, cwd);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, JSON.stringify(result, null, 2));
  console.log(`built facts for ${result.length} packages -> ${output}`);
}
