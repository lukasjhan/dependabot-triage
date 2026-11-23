import { readFile } from "node:fs/promises";
import { parse } from "yaml";
import type { Severity } from "./types.ts";

export type Config = {
  baseBranch: string | null;
  language: string;
  minSeverity: Severity;
  branchPrefix: string;
  labels: string[];
  devOnlyAutoDismiss: boolean;
  verify: string[];
  model: string;
  maxBudgetUsd: number;
};

const DEFAULTS: Config = {
  baseBranch: null,
  language: "en",
  minSeverity: "low",
  branchPrefix: "security/",
  labels: ["security", "dependencies"],
  devOnlyAutoDismiss: true,
  verify: [],
  model: "sonnet",
  maxBudgetUsd: 5,
};

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

export async function loadConfig(path: string): Promise<Config> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return DEFAULTS;
    throw err;
  }
  const doc = (parse(raw) ?? {}) as Record<string, unknown>;
  const devOnly = (doc.dev_only ?? {}) as Record<string, unknown>;
  const claude = (doc.claude ?? {}) as Record<string, unknown>;

  const config: Config = {
    baseBranch: optionalString(doc.base_branch, "base_branch") ?? DEFAULTS.baseBranch,
    language: optionalString(doc.language, "language") ?? DEFAULTS.language,
    minSeverity: (optionalString(doc.min_severity, "min_severity") as Severity | null) ?? DEFAULTS.minSeverity,
    branchPrefix: optionalString(doc.branch_prefix, "branch_prefix") ?? DEFAULTS.branchPrefix,
    labels: optionalStrings(doc.labels, "labels") ?? DEFAULTS.labels,
    devOnlyAutoDismiss: optionalBoolean(devOnly.auto_dismiss, "dev_only.auto_dismiss") ?? DEFAULTS.devOnlyAutoDismiss,
    verify: optionalStrings(doc.verify, "verify") ?? DEFAULTS.verify,
    model: optionalString(claude.model, "claude.model") ?? DEFAULTS.model,
    maxBudgetUsd: optionalNumber(claude.max_budget_usd, "claude.max_budget_usd") ?? DEFAULTS.maxBudgetUsd,
  };
  if (!SEVERITIES.includes(config.minSeverity)) throw new Error(`min_severity must be one of ${SEVERITIES.join(", ")}`);
  return config;
}

function optionalString(value: unknown, key: string): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw new Error(`${key} must be a string`);
  return value;
}

function optionalStrings(value: unknown, key: string): string[] | null {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) throw new Error(`${key} must be a list of strings`);
  return value;
}

function optionalBoolean(value: unknown, key: string): boolean | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "boolean") throw new Error(`${key} must be a boolean`);
  return value;
}

function optionalNumber(value: unknown, key: string): number | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "number" || value <= 0) throw new Error(`${key} must be a positive number`);
  return value;
}
