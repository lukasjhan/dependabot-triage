# dependabot-triage

A GitHub Action that triages your open Dependabot alerts with Claude. On each run it:

- opens **one pull request** with the fixes that are safe to apply automatically (lockfile refreshes and same-major overrides), verified by your own build and test commands
- opens **one report issue** listing what was patched, what needs a human decision and why, and how each vulnerability actually affects your code
- dismisses alerts for packages that never reach your production runtime

Unlike a plain version bump, every package gets an impact analysis grounded in your repository: where the vulnerable code is used, whether external input can reach it, and what to check before upgrading.

> This is a community project. It is not affiliated with or endorsed by GitHub.

## Requirements

- Dependabot alerts enabled on the repository
- A pnpm project (npm and yarn are planned)
- Node.js 24 or newer, and the project's dependencies installed before the action runs
- An Anthropic API key, or a Claude subscription token from `claude setup-token`

## Usage

```yaml
name: Dependabot triage

on:
  schedule:
    - cron: "0 23 * * 0"
  workflow_dispatch:
    inputs:
      dry_run:
        type: boolean
        default: true

permissions:
  contents: read

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - uses: pnpm/action-setup@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 24
          cache: pnpm

      - run: pnpm install --frozen-lockfile

      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ secrets.TRIAGE_APP_ID }}
          private-key: ${{ secrets.TRIAGE_APP_PRIVATE_KEY }}

      - uses: lukasjhan/dependabot-triage@v1
        with:
          github-token: ${{ steps.app-token.outputs.token }}
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          dry-run: ${{ github.event_name == 'workflow_dispatch' && inputs.dry_run }}
          settings: |
            verify:
              - pnpm lint
              - pnpm test
              - pnpm build
```

Scheduled runs publish for real. Manual runs default to a dry run, which writes the report to the job summary only.

Set `upload-report: true` to keep the JSON results and rendered markdown as a workflow artifact for 14 days. The artifact contains the analysis of your code, so it is visible to anyone who can read the repository's Actions runs.

## Configuration

Pass the configuration inline with the `settings` input, or keep it in `.github/dependabot-triage.yml`. `settings` wins when both are present. Every key is optional:

```yaml
base_branch: main            # default: the repository's default branch
language: en                 # language of the analysis text
min_severity: low            # low | medium | high | critical
branch_prefix: security/
labels: [security, dependencies]
dev_only:
  auto_dismiss: true
verify:                      # commands that must pass before a fix is kept
  - pnpm lint
  - pnpm test
  - pnpm build
claude:
  model: sonnet
  max_budget_usd: 5          # spending cap per run
```

## Authentication

The token needs these repository permissions:

| Permission | Access | Used for |
| --- | --- | --- |
| Contents | Read and write | pushing the fix branch |
| Pull requests | Read and write | opening the pull request |
| Issues | Read and write | opening the report issue |
| Dependabot alerts | Read and write | reading and dismissing alerts |

`GITHUB_TOKEN` cannot read Dependabot alerts, and pull requests it opens do not trigger your CI. Use one of:

- **GitHub App (recommended).** Create an app with the permissions above and webhooks disabled, install it on the repository, and mint a token with [`actions/create-github-app-token`](https://github.com/actions/create-github-app-token).
- **Fine-grained personal access token.** Scope it to the repository with the permissions above. Issues and pull requests will be authored by your account.

### Claude

Provide one of:

- `anthropic-api-key`: billed per use through the Anthropic API.
- `claude-code-oauth-token`: uses a Claude subscription. Run `claude setup-token` locally and store the token as a secret. Runs count against that account's usage limits, and the workflow stops working if the subscription ends.

## How it works

```
collect   open npm Dependabot alerts, advisory details, malware flag
facts     pnpm why (all and --prod), declared ranges, fix versions, changelogs
classify  Claude reads the facts and your code, returns a class and an impact analysis
apply     refresh the lockfile or add overrides, then run your verify commands
publish   dismiss dev-only alerts, push a branch, open the pull request and the issue
```

| Class | When | Outcome |
| --- | --- | --- |
| `lockfile` | the fix fits every declared range | pull request |
| `override` | outside a declared range, same major | pull request with a `pnpm.overrides` entry |
| `manual` | major or 0.x minor bump, no fix, verification failed, malware | issue only |
| `dev-only` | never reaches the production runtime | alert dismissed, listed in the issue |

Fixes newer than your `minimum-release-age` are deferred to a later run. Packages with an open Dependabot pull request are skipped.

## Security model

- Claude can only read the repository and run `npm view`. It returns JSON, and every write (dismissals, commits, pushes, issues, pull requests) is done by plain code that validates that JSON first.
- Advisory text, release notes and changelogs are passed to Claude as untrusted data. Links and mentions are stripped from its output.
- Hard rules Claude cannot override: malware is always `manual`, a class can only become more cautious than the computed hint, `dev-only` requires the package to be absent from the production tree, and failed verification demotes a fix to `manual`.

## Recommendations

- Turn off **Dependabot security updates** and keep **Dependabot alerts** on, so the same vulnerability does not get two pull requests.
- Keep `verify` close to your CI so a green pull request means a mergeable one.

## License

MIT
