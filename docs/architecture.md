# Architecture

The Claude-BugHunter bundle maps to a 6-phase workflow. Each phase has a focused set of skills; skills compose left-to-right as you move through the workflow.

The "Source" column tags each skill: `this repo` = original contribution, `shuvonsec` = vendored from [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty), `personal` = personal customization layered onto upstream content.

```
┌─────────┐  ┌─────────┐  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐
│ 1.SCOPE │→ │ 2.RECON │→ │ 3.HUNT  │→ │4.VALIDATE│→ │5.CAPTURE │→ │6.REPORT │
└─────────┘  └─────────┘  └─────────┘  └──────────┘  └──────────┘  └─────────┘
```

## Phase 1 — SCOPE (program intake, planning)

**Use when**: starting a new program, parsing scope, deciding what's in/out

| Skill | Source | Purpose |
|---|---|---|
| `bug-bounty` | shuvonsec | Master orchestrator — pulls in other skills as needed |
| `bb-methodology` | shuvonsec | 5-phase workflow + hunting mindset |
| `osint-methodology` | personal | Recon framework, asset graph, time budgeting |
| `hunt <target>` (shell) | this repo | Scaffolds `~/Targets/<name>/` with full template |

## Phase 2 — RECON (discovery)

**Use when**: asset enumeration, subdomain discovery, secret hunting, identity-fabric mapping

| Skill | Source | Purpose |
|---|---|---|
| `offensive-osint` | personal | 15-reference probe/regex/dork arsenal — loads on demand |
| `web2-recon` | shuvonsec | Subdomain enumeration, host discovery, URL crawling |
| `bb-local-toolkit` | personal | Router for local cloned bug-bounty repos |

## Phase 3 — HUNT (active testing)

**Use when**: testing for specific vulnerability classes

| Skill | Source | Purpose |
|---|---|---|
| 24 `hunt-*` skills | shuvonsec / public-skills-builder | One per vuln class — auto-trigger by topic |
| `security-arsenal` | shuvonsec | Payload library (XSS / SSRF / SQLi / SSTI / etc.) |
| `web3-audit` | shuvonsec | Smart-contract audit (10 bug classes, Foundry PoC) |
| `meme-coin-audit` | shuvonsec | Token rug-pull detection |

### Per-class hunt skills (24)

Each focuses on one vulnerability class with detection patterns, payloads, bypass tables, and chain opportunities drawn from disclosed bug-bounty reports.

```
hunt-rce            hunt-business-logic
hunt-sqli           hunt-race-condition
hunt-xss            hunt-cache-poison
hunt-ssrf           hunt-http-smuggling
hunt-xxe            hunt-ssti
hunt-idor           hunt-file-upload
hunt-csrf           hunt-auth-bypass
hunt-oauth          hunt-api-misconfig
hunt-graphql        hunt-cloud-misconfig
hunt-saml           hunt-subdomain
hunt-ato            hunt-llm-ai
hunt-mfa-bypass     hunt-misc
```

**How auto-triggering works**: just describe what you're testing — e.g., *"I see a `?url=` parameter on this endpoint"* — and Claude loads only `hunt-ssrf`. You don't invoke them by name.

## Phase 4 — VALIDATE (the gate before reporting)

**Use when**: you think you have a finding — BEFORE drafting any report

| Skill | Source | Purpose |
|---|---|---|
| `triage-validation` | shuvonsec | 7-Question Gate, 4 pre-submission gates, never-submit list |

Slash commands: `/triage`, `/validate`

The 7-Question Gate:

1. Can an attacker use this RIGHT NOW with a real HTTP request?
2. Is the impact on the program's accepted impact list?
3. Is the asset in scope?
4. Does it work without privileged access an attacker can't get?
5. Is this not already known or documented behavior?
6. Can impact be proved beyond "technically possible"?
7. Is this not on the never-submit list?

One NO = KILL. Move on. This single discipline is what separates productive researchers from the noise.

## Phase 5 — CAPTURE (evidence hygiene)

**Use when**: about to take a screenshot, export a HAR, or attach evidence

| Skill | Source | Purpose |
|---|---|---|
| **`evidence-hygiene`** | this repo | Cookie redaction, PII black-bar, HAR sanitization, screenshot capture order |

Covered protocols:
- Cookie redaction (which fields, what tools, screenshot timing)
- PII black-bar (other-user data, faces, addresses, SSNs)
- HAR file sanitization (jq filters)
- Burp screenshot hygiene (Repeater, Intruder, Proxy)
- DevTools Console PoC patterns
- Filename conventions for multi-step PoCs
- Post-submission rotation hygiene

## Phase 6 — REPORT (submission)

**Use when**: drafting the final report

| Skill | Source | Purpose |
|---|---|---|
| `report-writing` | shuvonsec | H1 / Bugcrowd / Intigriti / Immunefi templates, CVSS 3.1 + 4.0 |
| **`bugcrowd-reporting`** | this repo | Bugcrowd VRT search, severity-request paragraph, OOS rebuttals |

Slash command: `/report`

## Integration layer

Tools the skills call into during the workflow.

| Tool | Purpose |
|---|---|
| **Burp MCP** | Claude reads/replays HTTP traffic directly from Burp's proxy history. Eliminates manual paste-curl-into-chat workflow. |
| **`hunt` shell command** | Engagement-folder scaffold (`~/Targets/<name>/CLAUDE.md` + scope.md + findings/ + evidence/ + submissions.txt + notes.md + .gitignore). |
| **Anthropic API + Claude Max** | API for skill regeneration tools, Max for daily Claude Code usage. Two separate billing systems. |
| **HackerOne API** | Used by `public-skills-builder` to pull disclosed reports for fresh `hunt-*` skill content. |

## Composition example — full engagement walkthrough

```
1. SCOPE
   $ hunt acme-bb              → scaffolds ~/Targets/acme-bb/
   $ cd ~/Targets/acme-bb
   $ claude                    → opens Claude Code in this folder
   "Help me parse the program page into scope.md"
   → triggers bb-methodology, populates scope.md

2. RECON
   "Run external recon on *.acme.com"
   → triggers offensive-osint + web2-recon
   → suggests: certificate transparency, JS endpoint extraction, S3 enum

3. HUNT
   "I see /api/users/{id}/orders in JS — testing IDOR with two test accounts"
   → triggers hunt-idor
   → walks through detection patterns, payloads, two-account verification

4. VALIDATE
   /triage
   "I get back the victim's order data when I change the user_id"
   → 7-Question Gate
   → returns PASS (assuming all checks pass)

5. CAPTURE
   "About to take a screenshot of the IDOR PoC"
   → triggers evidence-hygiene
   → reminds you to redact cookies, mask victim PII

6. REPORT
   /report
   → triggers report-writing + bugcrowd-reporting
   → produces ready-to-paste body + VRT mapping + severity request paragraph
```

## Skill-loading mechanics

**Auto-trigger**: Skills load when their description matches your prompt. Skill matcher uses only the `description` field in the YAML frontmatter (the `triggers:` field is not officially supported and has no effect).

**Progressive disclosure**: Large skills (e.g., `offensive-osint`) keep SKILL.md lean and put detailed reference content in subfolders that load only when needed.

**Slash commands**: Some skills have explicit slash-command invocations (`/triage`, `/validate`, `/report`, `/recon`, `/hunt`, `/scope`, etc.) that force-load the relevant skill.

## What's NOT in the stack (intentional gaps)

- **No automated exploitation tooling** — this stack guides hunting and reporting; it doesn't fire payloads automatically. Use Burp's Active Scanner, sqlmap, etc. for automated work.
- **No CI/CD integration** — this is a workflow stack for individual researchers, not a continuous scanning pipeline.
- **No secret leak deletion** — if the stack helps you find leaked credentials, you (and the program) handle remediation.
- **No mobile-app testing skills** — out of scope for this repo. Use `Mobile-Security-Framework-MobSF` or Burp Mobile Assistant for Android/iOS work.

## Further reading

- [USAGE.md](../USAGE.md) — full usage walkthrough with worked example
- [INSTALL.md](../INSTALL.md) — step-by-step setup
- [docs/credits.md](credits.md) — full attribution to upstream sources
- [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) — community foundation
