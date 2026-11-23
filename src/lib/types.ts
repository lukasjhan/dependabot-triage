export type Severity = "low" | "medium" | "high" | "critical";

export type AdvisoryType = "reviewed" | "malware" | "unreviewed" | "unknown";

export type Alert = {
  number: number;
  url: string;
  createdAt: string;
  ecosystem: string;
  package: string;
  manifestPath: string;
  scope: "runtime" | "development" | null;
  relationship: "direct" | "transitive" | "unknown" | null;
  ghsa: string;
  cve: string | null;
  summary: string;
  description: string;
  references: string[];
  cwes: string[];
  severity: Severity;
  advisoryType: AdvisoryType;
  vulnerableRange: string;
  patchedVersion: string | null;
};

export type ClassHint = "no-fix" | "already-fixed" | "lockfile" | "override" | "breaking";

export type Edge = {
  parent: string;
  declaredRange: string | null;
  childVersion: string;
  via: string;
  targetSatisfies: boolean | null;
  parentFixVersion: string | null;
};

export type DirectDep = {
  name: string;
  declaredRange: string | null;
  dev: boolean;
  latest: string;
};

export type PackageFacts = {
  package: string;
  alerts: number[];
  severity: Severity;
  malware: boolean;
  targetVersion: string | null;
  targetPublishedAt: string | null;
  vulnerableRanges: string[];
  installed: string[];
  prodReachable: boolean;
  existingOverride: string | null;
  directVia: DirectDep[];
  edges: Edge[];
  changelogs: Changelog[];
  hint: ClassHint;
};

export type Changelog = {
  package: string;
  from: string;
  to: string;
  source: "releases" | "changelog-file" | null;
  repoUrl: string | null;
  compareUrl: string | null;
  text: string | null;
};

export type DecisionClass = "lockfile" | "override" | "manual" | "dev-only";

export type Decision = {
  package: string;
  alerts: number[];
  severity: Severity;
  class: DecisionClass;
  risk: "none" | "low" | "medium" | "high";
  reason: string;
  impact: string;
  usage: { file: string; line?: number; note: string }[];
  action: string;
  breakingChanges: string[];
  enforced: string[];
};

export type Classification = {
  packages: Decision[];
  excluded: { package: string; severity: Severity; alerts: number[] }[];
};

export type ApplyResult = {
  applied: { package: string; method: "lockfile" | "override"; from: string[]; to: string[] }[];
  deferred: { package: string; reason: "minimum-release-age"; availableAt: string }[];
  skipped: { package: string; reason: "dependabot-pr"; pr: number }[];
  failed: { package: string; reason: "existing-override" | "install-failed" | "not-resolved" | "verify-failed"; log: string }[];
  verify: { command: string; ok: boolean }[];
};
