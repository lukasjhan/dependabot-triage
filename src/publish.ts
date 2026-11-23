import { execFile } from "node:child_process";
import { appendFile, readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { GitHub, GitHubError } from "./lib/github.ts";
import type { Alert, ApplyResult, Classification, PackageFacts } from "./lib/types.ts";
import { issueBody, issueTitle, prBody, prTitle, type Report } from "./render.ts";

const exec = promisify(execFile);

export type PublishOptions = {
  cwd: string;
  out: string;
  base: string;
  branchPrefix: string;
  labels: string[];
  dryRun: boolean;
  dismissDevOnly: boolean;
  runId: string | null;
  manual: boolean;
  now?: Date;
};

export type PublishResult = { issue: number | null; pr: number | null; branch: string | null; dismissed: number[] };

export async function publish(gh: GitHub, report: Omit<Report, "label">, opts: PublishOptions): Promise<PublishResult> {
  const now = opts.now ?? new Date();
  const label = opts.manual ? `${now.toISOString().slice(0, 10)}${opts.runId ? `-${opts.runId}` : ""}` : isoWeek(now);
  const full: Report = { ...report, label };
  const devOnly = full.classification.packages.filter((d) => d.class === "dev-only").flatMap((d) => d.alerts);
  const hasPatch = full.apply.applied.length > 0;

  if (opts.dryRun) {
    const issue = issueBody(full, null);
    const pr = hasPatch ? prBody(full, null) : null;
    await mkdir(opts.out, { recursive: true });
    await writeFile(join(opts.out, "issue.md"), `# ${issueTitle(full)}\n\n${issue}\n`);
    if (pr) await writeFile(join(opts.out, "pr.md"), `# ${prTitle(full)}\n\n${pr}\n`);
    await summary(`# ${issueTitle(full)} (dry run)\n\n${issue}${pr ? `\n\n---\n\n# ${prTitle(full)}\n\n${pr}` : ""}`);
    return { issue: null, pr: null, branch: null, dismissed: [] };
  }

  if (opts.dismissDevOnly) for (const n of devOnly) await dismiss(gh, n);
  await ensureLabels(gh, opts.labels);

  const issue = await gh.request<{ number: number }>(`${gh.repoPath}/issues`, {
    method: "POST",
    body: JSON.stringify({ title: issueTitle(full), body: issueBody(full, null), labels: opts.labels }),
  });

  let pr: number | null = null;
  let branch: string | null = null;
  if (hasPatch) {
    branch = await pushBranch(gh, opts, `${opts.branchPrefix}${label}`, prTitle(full));
    const created = await gh.request<{ number: number }>(`${gh.repoPath}/pulls`, {
      method: "POST",
      body: JSON.stringify({ title: prTitle(full), head: branch, base: opts.base, body: prBody(full, issue.number) }),
    });
    pr = created.number;
    await gh.request(`${gh.repoPath}/issues/${pr}/labels`, { method: "POST", body: JSON.stringify({ labels: opts.labels }) });
    await gh.request(`${gh.repoPath}/issues/${issue.number}`, { method: "PATCH", body: JSON.stringify({ body: issueBody(full, pr) }) });
  }

  await summary(`Created #${issue.number}${pr ? ` and #${pr}` : ""} for ${issueTitle(full)}`);
  return { issue: issue.number, pr, branch, dismissed: opts.dismissDevOnly ? devOnly : [] };
}

async function dismiss(gh: GitHub, alert: number): Promise<void> {
  await gh.request(`${gh.repoPath}/dependabot/alerts/${alert}`, {
    method: "PATCH",
    body: JSON.stringify({
      state: "dismissed",
      dismissed_reason: "tolerable_risk",
      dismissed_comment: "dev-only: not included in the production runtime (dependabot-triage)",
    }),
  });
}

async function ensureLabels(gh: GitHub, labels: string[]): Promise<void> {
  for (const name of labels) {
    try {
      await gh.request(`${gh.repoPath}/labels/${encodeURIComponent(name)}`);
    } catch (err) {
      if (!(err instanceof GitHubError && err.status === 404)) throw err;
      await gh.request(`${gh.repoPath}/labels`, { method: "POST", body: JSON.stringify({ name, color: "d93f0b" }) });
    }
  }
}

async function pushBranch(gh: GitHub, opts: PublishOptions, wanted: string, message: string): Promise<string> {
  const branch = (await branchExists(gh, wanted)) && opts.runId ? `${wanted}-${opts.runId}` : wanted;
  const git = (...args: string[]) => exec("git", args, { cwd: opts.cwd });
  await git("checkout", "-b", branch);
  await git("add", "package.json", "pnpm-lock.yaml");
  await git("commit", "-m", message);
  const remote = `https://x-access-token:${gh.token}@github.com/${gh.owner}/${gh.repo}.git`;
  await git("-c", "http.https://github.com/.extraheader=", "push", remote, `HEAD:refs/heads/${branch}`);
  return branch;
}

async function branchExists(gh: GitHub, branch: string): Promise<boolean> {
  try {
    await gh.request(`${gh.repoPath}/branches/${encodeURIComponent(branch)}`);
    return true;
  } catch (err) {
    if (err instanceof GitHubError && err.status === 404) return false;
    throw err;
  }
}

async function summary(markdown: string): Promise<void> {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (file) await appendFile(file, `${markdown}\n`);
}

export function isoWeek(date: Date): string {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const day = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((d.getTime() - yearStart.getTime()) / 86_400_000 + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(week).padStart(2, "0")}`;
}

if (import.meta.main) {
  const [dir = "out", cwd = process.cwd()] = process.argv.slice(2);
  const read = async <T>(name: string) => JSON.parse(await readFile(join(dir, name), "utf8")) as T;
  const runId = process.env.GITHUB_RUN_ID ?? null;
  const server = process.env.GITHUB_SERVER_URL ?? "https://github.com";
  const result = await publish(
    GitHub.fromEnv(),
    {
      alerts: await read<Alert[]>("alerts.json"),
      facts: await read<PackageFacts[]>("facts.json"),
      classification: await read<Classification>("classification.json"),
      apply: await read<ApplyResult>("apply.json"),
      dismissDevOnly: process.env.TRIAGE_DISMISS_DEV_ONLY !== "false",
      runUrl: runId ? `${server}/${process.env.GITHUB_REPOSITORY}/actions/runs/${runId}` : null,
    },
    {
      cwd,
      out: dir,
      base: process.env.TRIAGE_BASE ?? "main",
      branchPrefix: process.env.TRIAGE_BRANCH_PREFIX ?? "security/",
      labels: (process.env.TRIAGE_LABELS ?? "security,dependencies").split(",").map((s) => s.trim()).filter(Boolean),
      dryRun: process.env.TRIAGE_DRY_RUN !== "false",
      dismissDevOnly: process.env.TRIAGE_DISMISS_DEV_ONLY !== "false",
      runId,
      manual: process.env.GITHUB_EVENT_NAME === "workflow_dispatch",
    },
  );
  console.log(JSON.stringify(result));
}
