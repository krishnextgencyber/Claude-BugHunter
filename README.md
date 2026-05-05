# Claude-BugHunter

A self-contained Claude Code skill bundle for bug hunting — bounty programs, authorized pentesting, CTFs, and personal vuln research.

40 skills + 15 slash commands + an engagement-scaffolding shell command, packaged as one repo. Clone, run a single installer, start hunting.

> Built on top of [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) and [shuvonsec/public-skills-builder](https://github.com/shuvonsec/public-skills-builder), with original skills, slash commands, and integration recipes for Burp Suite Pro's MCP server. Battle-tested through a real Bugcrowd engagement.

---

## What's in this repo

| Path | What it is |
|---|---|
| `skills/` | 40 SKILL.md bundles — workflow orchestrators, recon, 24 per-class `hunt-*` skills, validation, evidence hygiene, reporting |
| `commands/` | 15 slash commands — `/hunt`, `/recon`, `/triage`, `/validate`, `/report`, `/autopilot`, `/chain`, `/intel`, etc. |
| `scripts/hunt.sh` | `hunt <target>` shell function — scaffolds a per-engagement folder under `~/Targets/<name>/` with CLAUDE.md, scope.md, findings/, evidence/, submissions tracker |
| `scripts/install.sh` | Single installer — copies skills, commands, and the hunt scaffold into your `~/.claude/` and shell rc |
| `scripts/install-community-skills.sh` | Optional — refreshes the bundled upstream skills from shuvonsec's repos. Not needed for first-time setup. |
| `USAGE.md` | The detailed usage guide — workflow phases, decision tree, worked example |
| `docs/architecture.md` | High-level architecture diagram + skill-to-phase mapping |
| `docs/credits.md` | Attribution to upstream sources (shuvonsec, PortSwigger, Trail of Bits, etc.) |

---

## Quick install

```bash
git clone https://github.com/elementalsouls/Claude-BugHunter.git
cd Claude-BugHunter
./scripts/install.sh
```

That's it — skills go to `~/.claude/skills/`, commands to `~/.claude/commands/`, and `hunt.sh` is sourced from your shell rc.

Then in any new terminal:

```bash
hunt acme-test
```

That scaffolds `~/Targets/acme-test/` and you're ready to start.

For Burp MCP integration and the optional skill-regenerator setup, see [INSTALL.md](INSTALL.md).

---

## Architecture at a glance

The bundle maps to a 6-phase workflow:

```
1 SCOPE  →  2 RECON  →  3 HUNT  →  4 VALIDATE  →  5 CAPTURE  →  6 REPORT
```

Skills auto-trigger by topic mention. You don't invoke them by name — describe what you're testing and Claude loads the relevant skill.

| Phase | Use this | When |
|---|---|---|
| Scope | `bug-bounty`, `bb-methodology`, `osint-methodology` | Starting a new program |
| Recon | `offensive-osint`, `web2-recon`, `bb-local-toolkit` | Asset discovery, secret hunting |
| Hunt | 24 `hunt-*` per-class skills + `security-arsenal` | Active testing for specific vuln classes |
| Validate | `triage-validation` (`/triage`, `/validate`) | Before drafting any report |
| Capture | `evidence-hygiene` | Before any PoC screenshot |
| Report | `report-writing` + `bugcrowd-reporting` | Drafting submission |

See [USAGE.md](USAGE.md) for the full guide and [docs/architecture.md](docs/architecture.md) for a more detailed view.

---

## What's original vs. vendored

This bundle vendors upstream community skills so you can install everything in one step. Originals contributed by this repo:

1. **`bugcrowd-reporting`** — Bugcrowd-specific tactics: VRT category fallback hierarchy, severity-request paragraphs, OOS-clause rebuttal templates (rate limiting on auth-flow endpoints, debug-info framing, user-enumeration with sensitive PII, theoretical-issue counter), chained-finding cross-reference patterns
2. **`evidence-hygiene`** — cookie redaction protocols, PII black-bar discipline, HAR sanitization recipes, screenshot capture order, post-submission rotation hygiene. Covers the gap between "I captured a screenshot" and "I can safely attach this to a report"
3. **`hunt` shell command** — engagement-folder scaffolding for `~/Targets/<name>/`

Everything else is vendored from upstream — see [docs/credits.md](docs/credits.md) for full attribution and source mapping.

---

## Status

- ✅ 40 skills + 15 commands bundled, installable in one step
- ✅ Three original contributions (bugcrowd-reporting, evidence-hygiene, hunt.sh) production-ready
- ✅ Burp MCP integration documented and working
- ✅ Validated end-to-end on a real Bugcrowd engagement
- 🔄 HackerOne MCP integration is in upstream's repo but not yet wired into this stack

---

## Contributing

PRs welcome — especially for:
- Additional OOS rebuttal templates (per-program quirks across H1, Bugcrowd, Intigriti, Immunefi)
- Per-class `hunt-*` skills focused on specific industries (fintech, healthcare, gov)
- Improvements to the `hunt` shell scaffold (different platform conventions, alternate folder layouts)

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT — see [LICENSE](LICENSE). Original work in this repo is MIT-licensed.

Vendored upstream skills retain their original licenses (typically MIT — verify each upstream source listed in [docs/credits.md](docs/credits.md)). This repo does not relicense or claim authorship of vendored content.

---

## Credits

See [docs/credits.md](docs/credits.md) for full attribution. The short version:

- **[shuvonsec](https://github.com/shuvonsec)** — `claude-bug-bounty` foundation skills + `public-skills-builder` generator
- **archangel / douglasday** — pioneered the per-class `hunt-*` pattern that informed the architecture
- **[PortSwigger](https://portswigger.net)** — Burp Suite + MCP Server extension
- **[Trail of Bits](https://github.com/trailofbits/skills)** — skill-authoring discipline reference
- **[Anthropic](https://anthropic.com)** — Claude Code, the Skills protocol
