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
  severity: Severity;
  advisoryType: AdvisoryType;
  vulnerableRange: string;
  patchedVersion: string | null;
};
