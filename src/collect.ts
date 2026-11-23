import { writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { GitHub, GitHubError } from "./lib/github.ts";
import type { Alert, AdvisoryType } from "./lib/types.ts";

type RawAlert = {
  number: number;
  html_url: string;
  created_at: string;
  dependency: {
    package: { ecosystem: string; name: string };
    manifest_path: string;
    scope: "runtime" | "development" | null;
    relationship: "direct" | "transitive" | "unknown" | null;
  };
  security_advisory: {
    ghsa_id: string;
    cve_id: string | null;
    summary: string;
    description: string;
    severity: Alert["severity"];
    references: { url: string }[];
    cwes: { cwe_id: string }[];
  };
  security_vulnerability: {
    vulnerable_version_range: string;
    first_patched_version: { identifier: string } | null;
  };
};

export async function collect(gh: GitHub): Promise<Alert[]> {
  const raw = await gh.paginate<RawAlert>(`${gh.repoPath}/dependabot/alerts?state=open&ecosystem=npm&per_page=100`);
  const types = await advisoryTypes(gh, [...new Set(raw.map((a) => a.security_advisory.ghsa_id))]);

  return raw.map((a) => ({
    number: a.number,
    url: a.html_url,
    createdAt: a.created_at,
    ecosystem: a.dependency.package.ecosystem,
    package: a.dependency.package.name,
    manifestPath: a.dependency.manifest_path,
    scope: a.dependency.scope,
    relationship: a.dependency.relationship,
    ghsa: a.security_advisory.ghsa_id,
    cve: a.security_advisory.cve_id,
    summary: a.security_advisory.summary,
    description: a.security_advisory.description,
    references: a.security_advisory.references.map((r) => r.url),
    cwes: a.security_advisory.cwes.map((c) => c.cwe_id),
    severity: a.security_advisory.severity,
    advisoryType: types.get(a.security_advisory.ghsa_id) ?? "unknown",
    vulnerableRange: a.security_vulnerability.vulnerable_version_range,
    patchedVersion: a.security_vulnerability.first_patched_version?.identifier ?? null,
  }));
}

async function advisoryTypes(gh: GitHub, ids: string[]): Promise<Map<string, AdvisoryType>> {
  const entries = await Promise.all(
    ids.map(async (id): Promise<[string, AdvisoryType]> => {
      try {
        const adv = await gh.request<{ type: AdvisoryType }>(`/advisories/${id}`);
        return [id, adv.type];
      } catch (err) {
        if (err instanceof GitHubError && err.status === 404) return [id, "unknown"];
        throw err;
      }
    }),
  );
  return new Map(entries);
}

if (import.meta.main) {
  const out = process.argv[2] ?? "out/alerts.json";
  const alerts = await collect(GitHub.fromEnv());
  await mkdir(dirname(out), { recursive: true });
  await writeFile(out, JSON.stringify(alerts, null, 2));
  console.log(`collected ${alerts.length} open alerts -> ${out}`);
}
