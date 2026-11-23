import type { Alert, ApplyResult, Changelog, Classification, Decision, PackageFacts } from "./lib/types.ts";

export type Report = {
  label: string;
  alerts: Alert[];
  facts: PackageFacts[];
  classification: Classification;
  apply: ApplyResult;
  dismissDevOnly: boolean;
  runUrl: string | null;
};

const SEVERITY_ICON = { low: "⚪", medium: "🟡", high: "🟠", critical: "🔴" } as const;
const RISK_LABEL = { none: "none", low: "low", medium: "**medium**", high: "**high**" } as const;

export function issueTitle(r: Report): string {
  return `Dependabot triage ${r.label}`;
}

export function prTitle(r: Report): string {
  return `fix(deps): patch vulnerable dependencies (${r.label})`;
}

export function issueBody(r: Report, pr: number | null): string {
  if (r.alerts.length === 0) {
    return section("No open Dependabot alerts.", footer(r));
  }

  const decisions = new Map(r.classification.packages.map((d) => [d.package, d]));
  const applied = r.apply.applied.map((a) => decisions.get(a.package)!);
  const dismissed = r.classification.packages.filter((d) => d.class === "dev-only");
  const failed = new Map(r.apply.failed.map((f) => [f.package, f]));
  const review = r.classification.packages.filter((d) => d.class === "manual" || failed.has(d.package));
  const malware = r.facts.filter((f) => f.malware);

  const parts = [summary(r, pr, applied.length, review.length, dismissed.length)];

  if (malware.length > 0) {
    parts.push(
      section(
        "## 🚨 Malware",
        "These packages are flagged as malicious. Upgrading is not enough: remove them, rotate any secrets they could have read on developer machines or CI, and investigate.",
        malware.map((f) => `- \`${f.package}\` ${alertLinks(r, f.alerts)}`).join("\n"),
      ),
    );
  }

  if (applied.length > 0) {
    parts.push(
      section(
        `## ✅ Patched${pr ? ` in #${pr}` : ""}`,
        table(
          ["Package", "Alerts", "Change", "Method", "Risk"],
          r.apply.applied.map((a) => {
            const d = decisions.get(a.package)!;
            return [`\`${a.package}\``, alertLinks(r, d.alerts), `${a.from.join(", ")} → ${a.to.join(", ")}`, a.method, RISK_LABEL[d.risk]];
          }),
        ),
      ),
    );
  }

  if (review.length > 0) {
    parts.push(section("## ⚠️ Needs review", ...review.map((d) => reviewItem(r, d, failed.get(d.package)))));
  }

  if (r.apply.deferred.length > 0) {
    parts.push(
      section(
        "## ⏳ Deferred",
        "The fix is newer than the repository's `minimum-release-age`. It will be applied by a later run.",
        r.apply.deferred.map((d) => `- \`${d.package}\` available from ${d.availableAt.slice(0, 10)}`).join("\n"),
      ),
    );
  }

  if (r.apply.skipped.length > 0) {
    parts.push(
      section(
        "## ↪️ Skipped",
        r.apply.skipped.map((s) => `- \`${s.package}\` has an open Dependabot pull request #${s.pr}`).join("\n"),
      ),
    );
  }

  if (dismissed.length > 0) {
    parts.push(
      section(
        r.dismissDevOnly ? "## 🗂️ Dismissed (dev-only)" : "## 🗂️ Dev-only",
        r.dismissDevOnly
          ? "These packages do not reach the production runtime. Their alerts were dismissed as tolerable risk."
          : "These packages do not reach the production runtime. Their alerts were left open.",
        table(
          ["Package", "Alerts", "Severity", "Reason"],
          dismissed.map((d) => [
            `\`${d.package}\``,
            alertLinks(r, d.alerts),
            d.severity === "critical" ? "🔴 **critical (FYI)**" : `${SEVERITY_ICON[d.severity]} ${d.severity}`,
            d.reason,
          ]),
        ),
      ),
    );
  }

  if (r.classification.excluded.length > 0) {
    parts.push(
      section(
        "<details><summary>Below severity threshold</summary>",
        r.classification.excluded.map((e) => `- \`${e.package}\` ${e.severity} ${alertLinks(r, e.alerts)}`).join("\n"),
        "</details>",
      ),
    );
  }

  parts.push(footer(r));
  return parts.join("\n\n");
}

export function prBody(r: Report, issue: number | null): string {
  const decisions = new Map(r.classification.packages.map((d) => [d.package, d]));
  const factsByName = new Map(r.facts.map((f) => [f.package, f]));

  const parts: (string | null)[] = [
    issue ? `Refs #${issue}` : null,
    table(
      ["Package", "Alerts", "Change", "Method", "Risk"],
      r.apply.applied.map((a) => {
        const d = decisions.get(a.package)!;
        return [`\`${a.package}\``, alertLinks(r, d.alerts), `${a.from.join(", ")} → ${a.to.join(", ")}`, a.method, RISK_LABEL[d.risk]];
      }),
    ),
    ...r.apply.applied.map((a) => {
      const d = decisions.get(a.package)!;
      return section(`### \`${a.package}\``, analysis(d), changelogLinks(factsByName.get(a.package)?.changelogs ?? []));
    }),
    section("### Verification", r.apply.verify.map((v) => `- ${v.ok ? "✅" : "❌"} \`${v.command}\``).join("\n")),
  ];

  const pending = r.classification.packages.length - r.apply.applied.length;
  if (pending > 0) parts.push(`${pending} other package(s) need attention${issue ? `. See #${issue}` : ""}.`);
  parts.push(footer(r));
  return parts.filter(Boolean).join("\n\n");
}

function summary(r: Report, pr: number | null, applied: number, review: number, dismissed: number): string {
  const packages = new Set(r.alerts.map((a) => a.package)).size;
  const bits = [`**${r.alerts.length}** open alerts in **${packages}** packages`];
  if (applied) bits.push(`**${applied}** patched${pr ? ` in #${pr}` : ""}`);
  if (review) bits.push(`**${review}** need review`);
  if (dismissed) bits.push(`**${dismissed}** dev-only`);
  return bits.join(" · ");
}

function reviewItem(r: Report, d: Decision, failure?: ApplyResult["failed"][number]): string {
  const f = r.facts.find((x) => x.package === d.package);
  const head = `### \`${d.package}\` ${SEVERITY_ICON[d.severity]} ${d.severity} ${alertLinks(r, d.alerts)}`;
  const failNote = failure ? `> Automatic fix failed: \`${failure.reason}\`` : null;
  return section(head, failNote, analysis(d), d.action ? `**Action**\n\n${d.action}` : null, changelogLinks(f?.changelogs ?? []));
}

function analysis(d: Decision): string {
  const lines = [`**Risk:** ${RISK_LABEL[d.risk]} · ${d.reason}`];
  if (d.impact) lines.push(`**Impact:** ${d.impact}`);
  if (d.usage.length > 0) {
    lines.push(d.usage.map((u) => `- \`${u.file}${u.line ? `:${u.line}` : ""}\` ${u.note}`).join("\n"));
  }
  if (d.breakingChanges.length > 0) {
    lines.push(`**Breaking changes**\n\n${d.breakingChanges.map((b) => `- ${b}`).join("\n")}`);
  }
  return lines.join("\n\n");
}

function changelogLinks(changelogs: Changelog[]): string | null {
  const links = changelogs
    .map((c) => {
      const url = c.compareUrl ?? c.repoUrl;
      return url ? `[\`${c.package}\` ${c.from} → ${c.to}](${url})` : null;
    })
    .filter(Boolean);
  return links.length > 0 ? `**Changes:** ${links.join(" · ")}` : null;
}

function alertLinks(r: Report, numbers: number[]): string {
  return numbers
    .map((n) => {
      const a = r.alerts.find((x) => x.number === n);
      return a ? `[#${n}](${a.url})` : `#${n}`;
    })
    .join(" ");
}

function table(head: string[], rows: string[][]): string {
  const esc = (s: string) => s.replaceAll("|", "\\|").replaceAll("\n", " ");
  return [`| ${head.join(" | ")} |`, `| ${head.map(() => "---").join(" | ")} |`, ...rows.map((row) => `| ${row.map(esc).join(" | ")} |`)].join(
    "\n",
  );
}

function section(...parts: (string | null)[]): string {
  return parts.filter((p): p is string => Boolean(p)).join("\n\n");
}

function footer(r: Report): string {
  const run = r.runUrl ? ` · [run](${r.runUrl})` : "";
  return `<sub>Generated by dependabot-triage${run}</sub>`;
}
