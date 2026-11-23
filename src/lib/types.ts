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
