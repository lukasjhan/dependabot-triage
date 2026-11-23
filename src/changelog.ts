import semver from "semver";
import { GitHub, GitHubError } from "./lib/github.ts";
import { packument, type Manifest } from "./lib/registry.ts";
import type { Changelog } from "./lib/types.ts";

const MAX_TEXT = 20_000;
const MAX_RELEASE_PAGES = 3;
const VERSION_IN_TAG = /v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/;
const VERSION_IN_HEADING = /^#{1,4}\s.*?\[?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\]?/;
const VERSION_IN_TABLE_ROW = /^\|\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\s*\|/;

type Repo = { owner: string; name: string; directory: string | null };
type Release = { tag_name: string; body: string | null; draft: boolean };

export async function changelog(gh: GitHub, pkg: string, from: string, to: string): Promise<Changelog> {
  const base: Changelog = { package: pkg, from, to, source: null, repoUrl: null, compareUrl: null, text: null };
  const repo = await repository(pkg, to);
  if (!repo) return base;
  base.repoUrl = `https://github.com/${repo.owner}/${repo.name}`;

  const releases = await fetchReleases(gh, repo);
  const scoped = scopeToPackage(releases, pkg);
  const inRange = scoped.filter((r) => between(tagVersion(r.tag_name), from, to));
  const toTag = scoped.find((r) => tagVersion(r.tag_name) === to)?.tag_name;
  const fromTag = scoped.find((r) => tagVersion(r.tag_name) === from)?.tag_name ?? toTag?.replace(to, from);
  if (fromTag && toTag) base.compareUrl = `${base.repoUrl}/compare/${encodeURIComponent(fromTag)}...${encodeURIComponent(toTag)}`;

  const releaseText = inRange.map((r) => `## ${r.tag_name}\n\n${r.body ?? ""}`).join("\n\n");
  if (substantive(inRange)) return { ...base, source: "releases", text: truncate(releaseText) };

  const file = await changelogFile(gh, repo);
  const section = file ? sliceChangelog(file, from, to) : null;
  if (section) return { ...base, source: "changelog-file", text: truncate(section) };
  if (inRange.length > 0) return { ...base, source: "releases", text: truncate(releaseText) };
  return base;
}

async function repository(pkg: string, version: string): Promise<Repo | null> {
  const doc = await packument(pkg);
  const field: Manifest["repository"] = doc.versions[version]?.repository ?? doc.repository;
  if (!field) return null;
  const url = typeof field === "string" ? field : field.url;
  const match = url.match(/github\.com[/:]([^/]+)\/([^/#]+?)(?:\.git)?(?:#.*)?$/) ?? url.match(/^(?:github:)?([^/:]+)\/([^/]+)$/);
  if (!match) return null;
  return { owner: match[1], name: match[2], directory: typeof field === "string" ? null : (field.directory ?? null) };
}

async function fetchReleases(gh: GitHub, repo: Repo): Promise<Release[]> {
  const all: Release[] = [];
  for (let page = 1; page <= MAX_RELEASE_PAGES; page++) {
    const batch = await optional(gh.request<Release[]>(`/repos/${repo.owner}/${repo.name}/releases?per_page=100&page=${page}`));
    if (!batch?.length) break;
    all.push(...batch.filter((r) => !r.draft));
    if (batch.length < 100) break;
  }
  return all;
}

function scopeToPackage(releases: Release[], pkg: string): Release[] {
  const short = pkg.split("/").pop()!;
  const named = releases.filter((r) => r.tag_name.includes(short));
  return named.length > 0 ? named : releases;
}

async function changelogFile(gh: GitHub, repo: Repo): Promise<string | null> {
  const dirs = [...new Set([repo.directory, ""].filter((d): d is string => d !== null))];
  for (const dir of dirs) {
    for (const file of ["CHANGELOG.md", "changelog.md", "HISTORY.md"]) {
      const path = dir ? `${dir.replace(/\/$/, "")}/${file}` : file;
      const res = await optional(gh.request<{ content: string }>(`/repos/${repo.owner}/${repo.name}/contents/${path}`));
      if (res?.content) return Buffer.from(res.content, "base64").toString("utf8");
    }
  }
  return null;
}

function sliceChangelog(text: string, from: string, to: string): string | null {
  const out: string[] = [];
  let include = false;
  for (const line of text.split("\n")) {
    const row = line.match(VERSION_IN_TABLE_ROW);
    if (row) {
      if (between(row[1], from, to)) out.push(line);
      continue;
    }
    const heading = line.match(VERSION_IN_HEADING);
    if (heading) include = between(heading[1], from, to);
    if (include) out.push(line);
  }
  return out.length > 0 ? out.join("\n") : null;
}

function substantive(releases: Release[]): boolean {
  if (releases.length === 0) return false;
  const meaningful = releases.filter(
    (r) => (r.body ?? "").replace(/^\*\*Full Changelog\*\*:.*$/gm, "").replace(/\s+/g, "").length >= 40,
  );
  return meaningful.length * 2 >= releases.length;
}

function tagVersion(tag: string): string | null {
  return tag.match(VERSION_IN_TAG)?.[1] ?? null;
}

function between(version: string | null, from: string, to: string): boolean {
  return version !== null && semver.valid(version) !== null && semver.gt(version, from) && semver.lte(version, to);
}

function truncate(text: string): string {
  return text.length > MAX_TEXT ? `${text.slice(0, MAX_TEXT)}\n\n[truncated]` : text;
}

async function optional<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p;
  } catch (err) {
    if (err instanceof GitHubError && (err.status === 404 || err.status === 403)) return null;
    throw err;
  }
}
