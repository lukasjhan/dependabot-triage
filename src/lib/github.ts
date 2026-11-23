const API = process.env.GITHUB_API_URL ?? "https://api.github.com";

export class GitHubError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export class GitHub {
  readonly owner: string;
  readonly repo: string;
  readonly token: string;

  constructor(token: string, repository: string) {
    const [owner, repo] = repository.split("/");
    if (!owner || !repo) throw new Error(`invalid repository: ${repository}`);
    this.owner = owner;
    this.repo = repo;
    this.token = token;
  }

  static fromEnv(): GitHub {
    const token = process.env.GITHUB_TOKEN;
    const repository = process.env.GITHUB_REPOSITORY;
    if (!token) throw new Error("GITHUB_TOKEN is required");
    if (!repository) throw new Error("GITHUB_REPOSITORY is required");
    return new GitHub(token, repository);
  }

  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const res = await this.raw(path, init);
    return (res.status === 204 ? undefined : await res.json()) as T;
  }

  async paginate<T>(path: string): Promise<T[]> {
    const items: T[] = [];
    let next: string | null = path;
    while (next) {
      const res = await this.raw(next);
      items.push(...((await res.json()) as T[]));
      next = nextLink(res.headers.get("link"));
    }
    return items;
  }

  private async raw(path: string, init: RequestInit = {}): Promise<Response> {
    const url = path.startsWith("http") ? path : `${API}${path}`;
    const res = await fetch(url, {
      ...init,
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${this.token}`,
        "x-github-api-version": "2022-11-28",
        ...init.headers,
      },
    });
    if (!res.ok) {
      throw new GitHubError(res.status, `${init.method ?? "GET"} ${url} -> ${res.status} ${await res.text()}`);
    }
    return res;
  }

  get repoPath(): string {
    return `/repos/${this.owner}/${this.repo}`;
  }
}

function nextLink(header: string | null): string | null {
  if (!header) return null;
  for (const part of header.split(",")) {
    const match = part.match(/<([^>]+)>;\s*rel="next"/);
    if (match) return match[1];
  }
  return null;
}
