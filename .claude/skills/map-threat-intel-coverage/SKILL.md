---
name: map-threat-intel-coverage
description: >
  Analyze a threat-intel blog post or report against Stratus Red Team coverage.
  Extract cloud TTPs, classify each as Covered / Partial / Open issue / Not covered,
  produce a markdown coverage report, and suggest GitHub issue drafts for the gaps.
  Use when the user pastes a threat-intel URL (Microsoft, Mandiant, CrowdStrike, Unit 42, etc.)
  and asks for a coverage report, gap analysis, TTP extraction, or "what does Stratus cover
  from this report". Also use when given a local report file (.md, .txt, .pdf) or pasted text.
---

## Overview

Turn a threat-intel article into a saved markdown coverage report plus a list of *suggested* (never auto-created) GitHub issue drafts for any uncovered cloud TTPs.

## Inputs

- **URL** (primary): pass to `WebFetch` with prompt `"Return the full article text verbatim, including any IOC/TTP tables and section headings."`.
- **Local file path**: read with `Read`.
- **Pasted text**: use as-is.

Derive a short slug from the title/URL (e.g. `storm-2949`) for the output filename.

## Workflow

1. **Resolve input.** Fetch / read as above.

2. **Extract TTPs in kill-chain order, inline.** Build a table with columns `#`, `Phase` (the source's narrative phase, not MITRE tactic), `Technique`, `MITRE ATT&CK ID`, `Cloud/Surface`, one-sentence `What the attacker did`. Preserve the order described by the source. Do not delegate this step to a subagent — the article is already in context.

3. **Apply the scope filter** (below). Move out-of-scope TTPs into a separate "Out of scope" appendix with a one-line reason each, so the user can sanity-check the filter.

4. **Enumerate Stratus techniques.** Use paths relative to the repo root (find it with `git rev-parse --show-toplevel` if cwd isn't the repo root):
   - Docs (canonical technique IDs): `ls docs/attack-techniques/{AWS,azure,GCP,entra-id,EKS,kubernetes}/` — note the inconsistent casing.
   - Go source (implementation details): `v2/internal/attacktechniques/<platform>/<tactic>/<name>/main.go` — directories here are all lowercase (`aws`, `azure`, `eks`, `entra-id`, `gcp`, `k8s`).

   The doc files give a one-paragraph description; the Go code shows the exact SDK calls and resources touched. When verifying a candidate match, the subagent must read the Go file to confirm — the doc alone can be ambiguous.

5. **Enumerate open `kind/new-technique` issues.**
   `gh issue list --repo DataDog/stratus-red-team --state open --label kind/new-technique --limit 200 --json number,title,labels`

6. **Delegate coverage matching to one Explore subagent (single batch call).** Pass the in-scope TTP list, the technique-ID list from step 4, the open-issues JSON from step 5, and a pointer to `references/matching-heuristics.md`. Ask for a JSON array `[{ttp_index, status, evidence_id, other_platforms, justification}, ...]` where `other_platforms` is a list of `{platform, technique_id}` for same-concept techniques on other clouds (empty list if none). The subagent must:
   - Keyword-prefilter filenames first (≤ 5 doc reads per TTP).
   - For every Covered / Partial verdict, Read the corresponding `v2/internal/attacktechniques/<platform>/<tactic>/<name>/main.go` to confirm the implementation actually matches the TTP — doc descriptions are sometimes vague.

7. **Assemble the markdown report** (skeleton below) and save to `coverage-<slug>-<YYYY-MM-DD>.md` in the current working directory. Print the absolute path.

8. **Generate suggested issue drafts** for every `Not covered` row using `references/issue-template.md`. Run the approval flow (below).

9. **Stop.** No auto-creation. No commits.

## Scope filter

A TTP is **in scope** if and only if the attacker action is performed against a cloud-provider control plane (AWS, Azure, GCP, Entra ID, M365 admin, Kubernetes / EKS API server). On-host / endpoint actions inside a VM, container, or workstation are out of scope, even when the host runs in the cloud.

**IN (cloud control plane):**
1. Invoked `microsoft.web/sites/publishxml/action` to retrieve publishing credentials (ARM API)
2. Requested an OAuth token from IMDS at `169.254.169.254/metadata/identity/oauth2/token` (cloud identity surface)
3. Created an EKS access entry granting cluster-admin (EKS control plane)
4. Used Azure VM Run Command to execute a PowerShell script — the *invocation* is control-plane even though the script runs on-host

**OUT (endpoint / on-host):**
1. Disabled Defender real-time protection via PowerShell on the compromised VM (host-level)
2. Cleared Windows event logs with `wevtutil cl` (host-level)
3. Dumped LSASS with Mimikatz on a domain controller running in Azure (cloud host ≠ cloud action)
4. Renamed the ScreenConnect service to masquerade as a Windows component (host-level)

## Coverage statuses

- **Covered** — exact technique exists on the same platform (cite full ID).
- **Partial** — same platform, adjacent sub-action on the same service. Rare. Cross-cloud is **not** Partial.
- **Open issue** — tracked in an open `kind/new-technique` issue (cite `#NNN`).
- **Not covered** — no implementation, no tracking issue. **Cross-cloud equivalents do not count as coverage** — they surface in the `Other platforms` column instead.

Full rubric and worked examples: [references/matching-heuristics.md](references/matching-heuristics.md).

## Output report skeleton

```markdown
# Coverage report: <Report title>

- **Source:** <URL or file path>
- **Published:** <date if known>
- **Analyzed:** <YYYY-MM-DD>
- **Scope:** Cloud / cloud-identity TTPs only

## Summary
- In-scope TTPs: N
- Covered: X · Partial: X · Open issue: X · Not covered: X

## Kill chain
<3–6 sentence prose summary in attacker order>

## Coverage table
| # | Phase | TTP | MITRE | Cloud | Status | Stratus reference | Other platforms | Notes |

- `Stratus reference` — for **Covered** / **Partial**, a markdown link to the technique page using `[<technique-id>](https://stratus-red-team.cloud/attack-techniques/<PLATFORM_DIR>/<technique-id>/)`. `<PLATFORM_DIR>` matches the docs directory casing (`AWS`, `azure`, `GCP`, `entra-id`, `EKS`, `kubernetes`). For **Open issue**, link `[#NNN](https://github.com/DataDog/stratus-red-team/issues/NNN)`. For **Not covered**, `—`.
  Example: `[aws.credential-access.ec2-steal-instance-credentials](https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-steal-instance-credentials/)`
- `Other platforms` — same link format for same-concept techniques on other clouds, prefixed with the platform: e.g. `aws: [aws.credential-access.ec2-steal-instance-credentials](...)`. `—` if none. Informational only.

## Suggested new issues
### 1. New attack technique: <title>
**Labels:** `kind/new-technique`, `platform/<x>`, [`priority/seen-in-the-wild`]
<body using references/issue-template.md>

---

## Out of scope (endpoint-only)
- <TTP> — <one-line reason>
```

## Suggesting issues

Issue title pattern, body template, and label rules: [references/issue-template.md](references/issue-template.md).

After saving the report, print a compact preview (numbered titles + labels), then ask the user via `AskUserQuestion` with four options:

- **Create all** — file every draft via `gh issue create --repo DataDog/stratus-red-team` (HEREDOC body to preserve markdown). Print each created URL.
- **Review one by one** — per-draft `AskUserQuestion` with Create / Skip / Edit-then-create.
- **Print drafts only** — no creation; user files manually.
- **Cancel** — stop.

## Don't

- Never call `gh issue create` without explicit user approval.
- Never invent labels. Pick from: `kind/new-technique`, `platform/aws`, `platform/azure`, `platform/gcp`, `platform/entra-id`, `platform/eks`, `platform/k8s`, `priority/seen-in-the-wild`.
- Never include endpoint-only TTPs in the coverage table — they belong in the "Out of scope" appendix.
- Never mark a TTP **Covered** without citing a full technique ID (e.g. `azure.execution.vm-run-command`).
- Never output an infographic, HTML, or image. Markdown only.
