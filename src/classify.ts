import { spawn } from "node:child_process";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { Alert, Classification, Decision, DecisionClass, PackageFacts, Severity } from "./lib/types.ts";

const ROOT = join(import.meta.dirname, "..");
const SEVERITY: Severity[] = ["low", "medium", "high", "critical"];
const CAUTION: DecisionClass[] = ["lockfile", "override", "manual"];
const MAX_DESCRIPTION = 4_000;

type Options = {
  cwd: string;
  language: string;
  minSeverity: Severity;
  model?: string;
  maxBudgetUsd?: number;
};

type ClaudeDecision = Omit<Decision, "alerts" | "severity" | "enforced">;

export async function classify(facts: PackageFacts[], alerts: Alert[], opts: Options): Promise<Classification> {
  const threshold = SEVERITY.indexOf(opts.minSeverity);
  const included = facts.filter((f) => f.malware || SEVERITY.indexOf(f.severity) >= threshold);
  const excluded = facts.filter((f) => !included.includes(f)).map((f) => ({ package: f.package, severity: f.severity, alerts: f.alerts }));

  if (included.length === 0) return { packages: [], excluded };

  const prompt = await buildPrompt(included, alerts, opts.language);
  const output = await runClaude(prompt, opts).catch((err: Error) => {
    console.error(`classification unavailable: ${err.message}`);
    return { packages: [] as ClaudeDecision[] };
  });
  const byName = new Map(output.packages.map((p) => [p.package, p]));

  return {
    packages: included.map((f) => enforce(f, byName.get(f.package))),
    excluded,
  };
}

async function buildPrompt(facts: PackageFacts[], alerts: Alert[], language: string): Promise<string> {
  const template = await readFile(join(ROOT, "prompts/classify.md"), "utf8");
  const payload = facts.map((f) => ({
    ...f,
    advisories: alerts
      .filter((a) => f.alerts.includes(a.number))
      .map((a) => ({
        ghsa: a.ghsa,
        cve: a.cve,
        severity: a.severity,
        summary: a.summary,
        cwes: a.cwes,
        vulnerableRange: a.vulnerableRange,
        description: a.description.slice(0, MAX_DESCRIPTION),
      })),
  }));
  const data = JSON.stringify(payload, null, 2).replaceAll("</untrusted_data>", "<\\/untrusted_data>");
  return template.replace("{{language}}", language).replace("{{facts}}", data);
}

async function runClaude(prompt: string, opts: Options): Promise<{ packages: ClaudeDecision[] }> {
  const schema = await readFile(join(ROOT, "schema/classification.json"), "utf8");
  const args = [
    "-p",
    "--output-format",
    "json",
    "--json-schema",
    schema,
    "--tools",
    "Read,Grep,Glob,Bash",
    "--allowedTools",
    "Bash(npm view:*)",
    ...(opts.model ? ["--model", opts.model] : []),
    ...(opts.maxBudgetUsd ? ["--max-budget-usd", String(opts.maxBudgetUsd)] : []),
  ];
  const stdout = await run(process.env.CLAUDE_BIN ?? "claude", args, prompt, opts.cwd);
  const result = JSON.parse(stdout) as {
    is_error: boolean;
    subtype: string;
    num_turns: number;
    total_cost_usd: number;
    structured_output?: { packages: ClaudeDecision[] };
  };
  console.error(`claude: ${result.subtype}, ${result.num_turns} turns, $${result.total_cost_usd.toFixed(2)}`);
  if (result.is_error || !result.structured_output) throw new Error(`claude failed: ${result.subtype}`);
  return result.structured_output;
}

function run(cmd: string, args: string[], input: string, cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, stdio: ["pipe", "pipe", "inherit"] });
    let out = "";
    child.stdout.on("data", (chunk) => (out += chunk));
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve(out) : reject(new Error(`${cmd} exited with ${code}`))));
    child.stdin.end(input);
  });
}

function enforce(f: PackageFacts, d: ClaudeDecision | undefined): Decision {
  const floor = hintClass(f);
  const enforced: string[] = [];
  let decision: ClaudeDecision = d ?? {
    package: f.package,
    class: floor,
    risk: "medium",
    reason: "No analysis returned.",
    impact: "",
    usage: [],
    action: "Review this package manually.",
    breakingChanges: [],
  };
  if (!d) {
    decision = { ...decision, class: "manual" };
    enforced.push("missing-analysis");
  }

  if (decision.class === "dev-only" && (f.prodReachable || f.malware)) {
    decision = { ...decision, class: floor };
    enforced.push("dev-only-rejected");
  }
  if (decision.class !== "dev-only" && CAUTION.indexOf(decision.class) < CAUTION.indexOf(floor)) {
    decision = { ...decision, class: floor };
    enforced.push("upgrade-rejected");
  }
  if (f.malware && decision.class !== "manual") {
    decision = { ...decision, class: "manual" };
    enforced.push("malware");
  }

  return {
    ...sanitize(decision),
    package: f.package,
    alerts: f.alerts,
    severity: f.severity,
    enforced,
  };
}

function hintClass(f: PackageFacts): DecisionClass {
  switch (f.hint) {
    case "lockfile":
    case "already-fixed":
      return "lockfile";
    case "override":
      return "override";
    default:
      return "manual";
  }
}

function sanitize(d: ClaudeDecision): ClaudeDecision {
  return {
    ...d,
    reason: clean(d.reason),
    impact: clean(d.impact),
    action: clean(d.action),
    usage: d.usage.slice(0, 10).map((u) => ({ ...u, file: u.file.replace(/[^\w./@-]/g, ""), note: clean(u.note) })),
    breakingChanges: d.breakingChanges.slice(0, 5).map(clean),
  };
}

function clean(text: string): string {
  return text
    .replace(/\bhttps?:\/\/\S+/gi, "[link removed]")
    .replace(/<[^>]*>/g, "")
    .split(/(`[^`]*`)/)
    .map((part) => (part.startsWith("`") ? part : part.replace(/@[\w-]+(?:\/[\w.-]+)?/g, "`$&`")))
    .join("")
    .trim();
}

if (import.meta.main) {
  const [factsPath = "out/facts.json", alertsPath = "out/alerts.json", output = "out/classification.json", cwd = process.cwd()] =
    process.argv.slice(2);
  const facts = JSON.parse(await readFile(factsPath, "utf8")) as PackageFacts[];
  const alerts = JSON.parse(await readFile(alertsPath, "utf8")) as Alert[];
  const result = await classify(facts, alerts, {
    cwd,
    language: process.env.TRIAGE_LANGUAGE ?? "en",
    minSeverity: (process.env.TRIAGE_MIN_SEVERITY as Severity | undefined) ?? "low",
    model: process.env.TRIAGE_MODEL,
    maxBudgetUsd: process.env.TRIAGE_MAX_BUDGET_USD ? Number(process.env.TRIAGE_MAX_BUDGET_USD) : undefined,
  });
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, JSON.stringify(result, null, 2));
  console.log(`classified ${result.packages.length} packages (${result.excluded.length} excluded) -> ${output}`);
}
