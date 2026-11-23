import { appendFile, access, mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { apply } from "./apply.ts";
import { classify } from "./classify.ts";
import { collect } from "./collect.ts";
import { facts as buildFacts } from "./facts.ts";
import { loadConfig } from "./lib/config.ts";
import { GitHub } from "./lib/github.ts";
import { publish } from "./publish.ts";

const [major] = process.versions.node.split(".").map(Number);
if (major < 24) throw new Error(`dependabot-triage needs Node.js 24 or newer, found ${process.version}`);

const cwd = resolve(process.env.TRIAGE_WORKDIR ?? process.cwd());
const out = resolve(process.env.TRIAGE_OUT ?? join(cwd, ".dependabot-triage"));
const dryRun = process.env.TRIAGE_DRY_RUN === "true";
const config = await loadConfig(resolve(cwd, process.env.TRIAGE_CONFIG ?? ".github/dependabot-triage.yml"));
const gh = GitHub.fromEnv();

await access(join(cwd, "node_modules")).catch(() => {
  throw new Error("node_modules not found: install the project's dependencies before running dependabot-triage");
});
await mkdir(out, { recursive: true });
const save = (name: string, data: unknown) => writeFile(join(out, name), JSON.stringify(data, null, 2));

const base = config.baseBranch ?? (await gh.request<{ default_branch: string }>(gh.repoPath)).default_branch;

const alerts = await collect(gh);
await save("alerts.json", alerts);
console.log(`collected ${alerts.length} open npm alerts`);

const facts = await buildFacts(gh, alerts, cwd);
await save("facts.json", facts);

const classification = await classify(facts, alerts, {
  cwd,
  language: config.language,
  minSeverity: config.minSeverity,
  model: config.model,
  maxBudgetUsd: config.maxBudgetUsd,
});
await save("classification.json", classification);

const applied = await apply(gh, classification, facts, { cwd, verify: config.verify });
await save("apply.json", applied);
console.log(
  `applied ${applied.applied.length}, deferred ${applied.deferred.length}, skipped ${applied.skipped.length}, failed ${applied.failed.length}`,
);

const runId = process.env.GITHUB_RUN_ID ?? null;
const server = process.env.GITHUB_SERVER_URL ?? "https://github.com";
const result = await publish(
  gh,
  {
    alerts,
    facts,
    classification,
    apply: applied,
    dismissDevOnly: config.devOnlyAutoDismiss,
    runUrl: runId ? `${server}/${gh.owner}/${gh.repo}/actions/runs/${runId}` : null,
  },
  {
    cwd,
    out,
    base,
    branchPrefix: config.branchPrefix,
    labels: config.labels,
    dryRun,
    dismissDevOnly: config.devOnlyAutoDismiss,
    runId,
    manual: process.env.GITHUB_EVENT_NAME === "workflow_dispatch",
  },
);
console.log(JSON.stringify(result));

if (process.env.GITHUB_OUTPUT) {
  await appendFile(
    process.env.GITHUB_OUTPUT,
    [`issue-number=${result.issue ?? ""}`, `pr-number=${result.pr ?? ""}`, `report-dir=${out}`].join("\n") + "\n",
  );
}
