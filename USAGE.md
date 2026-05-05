# Claude-BugHunter — Usage Guide

A practical guide to using the 40-skill Claude-BugHunter bundle for bug hunting (bounty programs, authorized pentesting, CTFs, vuln research). This document covers what's in the bundle, how it composes, and how to use it on a real engagement from intake through paid bounty.

> Built and validated through a real Bugcrowd engagement on a major financial target. The engagement exposed four capability gaps in a starter 3-skill stack; the final stack documented here fixes all four and adds 30+ new skills, a Burp MCP integration, and engagement scaffolding.

---

## 1. Architecture overview

The stack maps to a 6-phase bug-bounty workflow. Each phase has its own skill set; skills compose left-to-right through the workflow.

```
1 SCOPE  →  2 RECON  →  3 HUNT  →  4 VALIDATE  →  5 CAPTURE  →  6 REPORT
```

| Phase | What you're doing | Primary skills |
|---|---|---|
| **1. Scope** | Reading program rules, deciding what's in/out, scaffolding the engagement folder | `bug-bounty`, `bb-methodology`, `osint-methodology` + `hunt <target>` shell command |
| **2. Recon** | Asset discovery, subdomain enum, endpoint mapping, secret hunting | `offensive-osint`, `web2-recon`, `bb-local-toolkit` |
| **3. Hunt** | Active testing for bugs in specific vuln classes | 24 `hunt-*` skills (auto-trigger by class) + `security-arsenal` (payloads) |
| **4. Validate** | Decide whether a lead is actually a reportable bug | `triage-validation` (7-Question Gate) via `/triage` or `/validate` |
| **5. Capture** | PoC screenshots, HAR files, evidence redaction | `evidence-hygiene` |
| **6. Report** | Draft and submit | `report-writing`, `bugcrowd-reporting` |

See [docs/architecture.md](docs/architecture.md) for a more detailed breakdown.

---

## 2. Skill inventory (40 skills total)

### Workflow skills — the spine of any engagement

| Skill | Purpose | Auto-triggers on |
|---|---|---|
| `bug-bounty` | Master orchestrator — pulls in other skills as needed | "start a hunt", "bug bounty workflow" |
| `bb-methodology` | 5-phase workflow + hunting mindset | "how do I plan", "where do I start" |
| `osint-methodology` | Recon framework, asset graph, time budgeting | "how to scope", "external recon plan" |

### Recon — discovery layer

| Skill | Purpose | Auto-triggers on |
|---|---|---|
| `offensive-osint` | 15-reference probe/regex/dork arsenal — loads on demand | subdomain enum, secret scanning, GraphQL discovery, identity fabric |
| `web2-recon` | Subdomain enumeration, host discovery, URL crawling | "find all subdomains of X" |
| `bb-local-toolkit` | Router for local cloned bug-bounty repos | "which tool for X", refers to local stack |

### Hunt — 24 per-class skills

Each focuses on one vulnerability class with detection patterns, payloads, bypass tables, and chain opportunities drawn from disclosed bug-bounty reports.

| Skill | Class |
|---|---|
| `hunt-rce` | Remote code execution (highest payouts) |
| `hunt-sqli` | SQL injection / NoSQL injection |
| `hunt-xss` | Reflected, stored, DOM, blind XSS |
| `hunt-ssrf` | Server-side request forgery + 11 IP bypass techniques |
| `hunt-xxe` | XML external entity |
| `hunt-idor` | IDOR / broken object-level authorization |
| `hunt-csrf` | Cross-site request forgery (chain-required) |
| `hunt-oauth` | OAuth 2.0 / OIDC flaws |
| `hunt-graphql` | GraphQL-specific (introspection, APQ bypass, node() IDOR) |
| `hunt-saml` | SAML / SSO attacks (XSW, signature stripping) |
| `hunt-ato` | 9 paths to account takeover |
| `hunt-mfa-bypass` | 7 MFA / 2FA bypass patterns |
| `hunt-business-logic` | Logic flaws (race-condition double-spend, coupon abuse) |
| `hunt-race-condition` | Concurrency bugs (TOCTOU, parallel-request exploits) |
| `hunt-cache-poison` | Web cache poisoning + cache deception |
| `hunt-http-smuggling` | CL.TE / TE.CL / H2.CL request smuggling |
| `hunt-ssti` | Server-side template injection (Jinja2, Twig, Freemarker, ERB) |
| `hunt-file-upload` | File upload bypass (10 techniques: double ext, magic bytes, polyglot) |
| `hunt-auth-bypass` | Broken auth / access control |
| `hunt-api-misconfig` | Mass assignment, JWT attacks, prototype pollution, CORS |
| `hunt-cloud-misconfig` | AWS/GCP/Azure/K8s misconfigurations |
| `hunt-subdomain` | Subdomain takeover (27+ provider fingerprints) |
| `hunt-llm-ai` | Prompt injection, ASCII smuggling, agentic AI bugs |
| `hunt-misc` | Catch-all for less-common classes |

**How auto-triggering works**: just describe what you're testing — e.g., *"I see a `?url=` parameter on this endpoint"* — and Claude loads only `hunt-ssrf`. You don't invoke them by name. The skill matcher looks at your prose and triggers based on the description field.

### Hunt support — payloads and specialized

| Skill | Purpose |
|---|---|
| `security-arsenal` | XSS / SSRF / SQLi / SSTI / IDOR / SAML payload library |
| `web3-audit` | Smart-contract audit (10 bug classes, Foundry PoC template) |
| `meme-coin-audit` | Token rug-pull detection |

### Validate — the gate before reporting

| Skill | Purpose | Slash command |
|---|---|---|
| `triage-validation` | 7-Question Gate, 4 pre-submission gates, never-submit list | `/triage`, `/validate` |

### Capture — evidence hygiene

| Skill | Purpose |
|---|---|
| `evidence-hygiene` | Cookie redaction, PII black-bar, HAR sanitization, Burp/Console screenshot patterns |

### Report — submission

| Skill | Purpose | Slash command |
|---|---|---|
| `report-writing` | H1 / Bugcrowd / Intigriti / Immunefi report templates, CVSS 3.1 + 4.0 | `/report` |
| `bugcrowd-reporting` | Bugcrowd-specific: VRT search, severity-request paragraph, OOS rebuttals | (loaded with report-writing) |

---

## 3. Integration layer

| Tool | Purpose | Setup |
|---|---|---|
| **Burp MCP** | Claude reads/replays HTTP traffic directly from Burp's proxy history — eliminates manual paste-curl-into-chat | Burp Suite + MCP Server extension (port 9876) → `claude mcp add burp -s user -- java -jar ~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar` |
| **`hunt <target>` shell command** | Scaffolds `~/Targets/<name>/` with CLAUDE.md, scope.md, findings/, evidence/, submissions.txt | `source ~/.claude/scripts/hunt.sh` in your `.zshrc` |
| **Anthropic API (separate from Claude Max)** | Powers `public-skills-builder` for periodic skill regeneration | `console.anthropic.com/billing` → API key → `export ANTHROPIC_API_KEY=...` |
| **HackerOne API** | Pulls disclosed reports for the skill builder | `hackerone.com/settings/api_token` → `H1_API_KEY=username:token` in `.env` |

**Important — Claude Max ≠ API.** Claude Max gives you Claude Code + chat. The Anthropic API is pay-per-token, billed separately. You need both keys if you want to run skill-generation tools.

---

## 4. Decision tree — which skill for which task

| Task / question | Skill(s) |
|---|---|
| "I want to start a new engagement on `target.com`" | Run `hunt target` (shell command). Read the generated CLAUDE.md. |
| "How should I plan this hunt?" | `bb-methodology` + `osint-methodology` |
| "Find subdomains / endpoints / leaked secrets" | `offensive-osint` + `web2-recon` |
| "Which tool from my local stack does X?" | `bb-local-toolkit` |
| "I'm hunting [vuln class]" | `hunt-<class>` (auto-triggers on class mention) |
| "What's the payload that bypasses [filter]?" | `security-arsenal` |
| "Smart-contract audit for [protocol]" | `web3-audit` (or `meme-coin-audit` for tokens) |
| "I think I found a bug — should I report it?" | Run `/triage` (decides PASS / KILL / DOWNGRADE / CHAIN-REQUIRED) |
| "About to take a screenshot of my PoC" | Read `evidence-hygiene` first (cookie + PII redaction) |
| "Need to sanitize a HAR file before attaching" | `evidence-hygiene` §4 (jq filter) |
| "Drafting a report" | `/report` invokes `report-writing` (+ `bugcrowd-reporting` if Bugcrowd) |
| "Triager closed as OOS" | `bugcrowd-reporting` §4 OOS rebuttal templates |
| "Triager downgraded my severity" | `bugcrowd-reporting` §3 severity-request paragraph |
| "I have linked findings — how to chain?" | `bugcrowd-reporting` §5 chain cross-reference patterns |
| "Need to refresh hunt-* skills with newer disclosed reports" | Run `public-skills-builder` (requires Anthropic + H1 API keys) |

---

## 5. Worked example — full engagement walkthrough

### Step 1 — Scaffold

```bash
hunt acme-bb
cd ~/Targets/acme-bb
```

This creates `CLAUDE.md`, `scope.md`, `findings/`, `evidence/`, `submissions.txt`, `notes.md`, `.gitignore`. Open Claude Code from this directory:

```bash
claude
```

### Step 2 — Read program rules and fill scope.md

Tell Claude:
> *"Here's the program page text: [paste]. Help me parse the scope and OOS into scope.md."*

Claude triggers `bb-methodology` and walks through the program rules, populating in-scope assets, OOS, focus areas, bounty bands, and engagement rules.

### Step 3 — Recon

> *"Run a recon pass on `*.acme.com`. I want subdomains, exposed APIs, S3 buckets, and any leaked secrets in JS bundles."*

Claude triggers `offensive-osint` and `web2-recon`. If Burp MCP is connected, Claude can replay requests from your browser session directly.

### Step 4 — Hunt a specific class

> *"I see `/api/users/{id}/orders` in the JS bundle. Going to test for IDOR with two test accounts."*

Claude triggers `hunt-idor`. It walks through detection patterns, suggests payloads (HTTP method swap, array wrap, GraphQL node() resolver), and reminds you to verify with two accounts.

### Step 5 — Validate before drafting

You think you have a finding. Before writing anything:

```
/triage
```

Or describe the finding to Claude. The `triage-validation` skill runs the 7-Question Gate:

- Q1: Real HTTP request? Show me.
- Q2: Accepted impact per program?
- Q3: In scope?
- Q4: No admin-only assumption?
- Q5: Not already known / by design?
- Q6: Beyond "technically possible"? (Show actual victim data, not just 200 OK)
- Q7: Not on the never-submit list?

You get back **PASS**, **KILL**, **DOWNGRADE**, or **CHAIN REQUIRED**. If KILL — move on, don't draft. (This single step would have saved hours of wasted drafting on countless engagements.)

### Step 6 — Capture evidence

Before any screenshot, tell Claude:

> *"I'm about to capture a PoC screenshot of the IDOR. What do I need to redact?"*

Claude triggers `evidence-hygiene`. You get the cookie redaction protocol, PII black-bar rules, and the screenshot capture order. If you're using Burp Repeater, Claude reminds you to drag the divider down to hide the cookie panel.

### Step 7 — Draft and submit

```
/report
```

Claude triggers `report-writing` (for the body template) and `bugcrowd-reporting` (for VRT mapping, severity request, OOS rebuttals if relevant). The output is a copy-paste-ready report.

### Step 8 — Track

Once submitted, append to `submissions.txt`:

```
<UUID>  P1  2FA Bypass  ATO via missing step-up on credential-change endpoint
```

Cross-reference this UUID in any chained submissions you file later.

---

## 6. Setup for someone new

If another pentester wants to replicate this stack, the install steps are in [INSTALL.md](INSTALL.md). The short version:

1. Clone this repo
2. Run `./scripts/install.sh` (installs all 40 skills, 15 commands, and hunt scaffold in one step)
3. Set up Burp MCP (BApp Store extension + `claude mcp add burp ...`)
4. (Optional) Refresh upstream snapshots via `./scripts/install-community-skills.sh`
5. (Optional) Set up the skill regenerator with Anthropic + H1 API keys

Total setup time: ~10 minutes including Burp MCP.

---

## 7. The discipline this stack enforces

Beyond the skills themselves, the stack enforces three habits that separate productive bug-bounty researchers from the noise:

1. **Validate before drafting.** `triage-validation`'s 7-Question Gate kills weak findings in 30 seconds. Submitting one well-validated P3 is better than three half-baked P4s, and dramatically better for your researcher reputation.

2. **Redact by default.** `evidence-hygiene` makes redaction the first step of evidence capture, not an afterthought. Every screenshot you take is reflexively cookie-safe and PII-safe.

3. **Specificity in reporting.** `bugcrowd-reporting`'s OOS rebuttal templates and severity-request paragraph turn a P4 default into a P3 outcome more often than not. Triagers respect specificity; they auto-close vagueness.

The validation engagement that produced this stack illustrated all three: the original engagement submitted some findings that were "API behavior observed" without exploitation proof (would have been killed by Q6). The new stack would have caught those at the gate.

---

## 8. Limitations and known issues

- **`offensive-osint` is large**, even after refactor. The 15 reference files load on demand, but the SKILL.md still consumes context on every trigger. Future work: split into smaller sub-skills if context becomes a bottleneck.
- **Per-class `hunt-*` skills overlap on borderline classes.** A finding that's both IDOR and business-logic may trigger two skills. Manageable, but worth knowing.
- **`public-skills-builder` is rough.** The script needs Python 3.10+, has hardcoded `master` branch references, and requires `--program` for H1 queries. Patches documented in INSTALL.md.
- **No HackerOne MCP yet.** Burp MCP works; H1 MCP is in shuvonsec's repo but not configured here. Worth adding when you start hunting H1 programs.
- **No engagement-coordinator skill.** Cross-finding tracking and submission ID management is currently manual via `submissions.txt`. Future skill candidate.

---

## 9. Suggested next iterations

If you keep using this and want to extend it:

1. **Per-engagement memory** — extend `bb-methodology` to record patterns you've seen pay off across engagements. After 5+ engagements, your personal patterns will outperform the disclosed-report patterns.
2. **HackerOne MCP integration** — wire up the H1 MCP in shuvonsec's repo for live duplicate-search and program intel during reports.
3. **Specialized `hunt-*` skills** for high-payout niches you focus on (e.g., `hunt-fintech-graphql`, `hunt-healthcare-fhir`).
4. **A `program-rules-parser` skill** that takes program text and produces a structured `scope.md` automatically.
5. **Engagement-coordinator skill** that auto-updates `submissions.txt` and surfaces chain candidates.

These are nice-to-haves. The current stack is production-grade as-is.

---

## 10. Credits

See [docs/credits.md](docs/credits.md) for full attribution.
