---
name: hunt-http-smuggling
description: "Hunt HTTP request smuggling (CL.TE, TE.CL, H2.CL, H2.TE). Cause: front-end proxy and back-end server disagree on where one request ends and the next begins (Content-Length vs Transfer-Encoding header parsing inconsistency). CL.TE: front-end uses CL, back uses TE → smuggle by sending TE: chunked but with body that fits CL count. TE.CL: opposite. H2.CL: HTTP/2 downgrade, smuggle CL into HTTP/1.1 back-end. Detection tools: Burp HTTP Request Smuggler extension, smuggler.py, h2csmuggler. Confirm: time-delay technique (smuggled GET with 30s timeout) — if front-end returns slow on next victim request, smuggling works. Validate: cache poisoning chain (smuggle request that gets cached for victim), credential theft (smuggle X-Forwarded-For override that captures next user's cookies), bypass auth (smuggled internal-path request). Real paid examples from major CDN deployments. Use when hunting H1 paid programs running CDN+origin stacks, when targeting load balancer / WAF bypass."
---

## 17. HTTP REQUEST SMUGGLING
> Lowest dup rate. $5K–$30K. PortSwigger research by James Kettle.

### CL.TE (Content-Length front, Transfer-Encoding back)
```http
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### Detection
```
1. Burp extension: HTTP Request Smuggler
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. Manual timing: CL.TE probe + ~10s delay = backend waiting for rest of body
```

### Impact Chain
```
Poison next request → access admin as victim
Steal credentials → capture victim's session
Cache poisoning → stored XSS at scale
```

---

## Target-Suitability Matrix (2026 reality check)

The classic CL.TE / TE.CL payloads are NOT universally exploitable in 2026. Modern proxies are RFC 9112 strict by default. Fingerprint the front-end BEFORE investing time.

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notes |
|---|---|---|---|---|---|
| **Nginx ≥ 1.21** | NO | NO | partial (H2 ingress) | partial | RFC-strict; rejects CL+TE with HTTP 400. Verified locally on Nginx 1.27 — all 9 documented variants killed by front-end ([docs/verification/phase2h-smuggling-cachepoison.md](../../docs/verification/phase2h-smuggling-cachepoison.md)). |
| **Caddy 2.x** | NO | NO | — | — | Hardened by default |
| **Envoy ≥ 1.20** | NO | NO | partial | partial | Hardened in most paths |
| **HAProxy ≤ 2.4** | ✓ | ✓ | — | — | **Vulnerable**, see CVE-2021-40346 |
| **AWS ALB + specific upstream** | partial | partial | ✓ | ✓ | Several disclosed-paid reports 2022-2024 |
| **Cloudflare → S3 / Lambda chains** | — | — | ✓ | ✓ | H2-downgrade attacks remain viable |
| **Older F5 BIG-IP (TMM < 16)** | ✓ | — | — | — | Vendor advisories |
| **Citrix ADC / NetScaler (older firmware)** | ✓ | ✓ | — | — | Disclosed in 2020-2022 |
| **Squid 3.x** | ✓ | — | — | — | Older deployments |
| **Apache Traffic Server (older)** | ✓ | ✓ | ✓ | ✓ | PortSwigger research |
| **Custom Python / Go proxies** | ✓ | ✓ | — | — | Frequently miss RFC enforcement |

### Operator fingerprint quick-check

```bash
curl -sI https://target/ | grep -i "Server:"
```

- `nginx/1.21+`, `Caddy`, `envoy` → CL/TE classic is dead — pivot to H2.CL/H2.TE if the front-end speaks HTTP/2, or look for legacy proxies upstream
- `HAProxy`, header points to AWS/CDN → run the full payload matrix
- No Server header → assume hardened, but run a single quick `space-before-colon` probe; if it doesn't 400, dig deeper

### H2.CL / H2.TE (the modern dominant vector)

H2-downgrade smuggling attacks rely on the front-end speaking HTTP/2 to the client and HTTP/1.1 to origin. The downgrade introduces CL/TE confusion because HTTP/2's frame-length headers don't survive the conversion cleanly. Most CDN+origin chains in 2024-2026 use this exact topology.

Tools that send HTTP/2 raw frames (Burp Pro's HTTP Request Smuggler extension, `h2csmuggler`, `smuggler.py`) are the right starting point against CDN-fronted targets. Avoid HTTP/1.1-only test clients (curl, raw sockets) against H2-front-ended targets — you'll send the wrong protocol entirely.

### TE.0 / 0.CL / CL.0 / Expect-desync (2024-2025 dominant variants)

The classic CL.TE/TE.CL framing assumes the body *length* is the disagreement. The newer family is about one side seeing **no body at all**:

- **CL.0** — front-end forwards the request, back-end ignores `Content-Length` and treats the request as bodyless → your body is parsed as the *next* request on that connection. Targets endpoints that drop CL (static handlers, redirects, OPTIONS).
- **0.CL** — inverse: front-end sees implicit-zero length, back-end honours `Content-Length`. Kettle's 2025 work shows a **double-desync** converting 0.CL→CL.0 to make it exploitable.
- **TE.0** — the CL.0 analogue driven by `Transfer-Encoding`: front-end honours `TE: chunked`, back-end treats it as `Content-Length: 0`. Hit **thousands of Google Cloud Load Balancer / IAP** hosts (Arnolfo, Gregorio, @_medusa_1_, Bugcrowd 2024 — $8.5K).
- **Expect-based desync** — `Expect: 100-continue` (and obfuscated forms like `Expect: y 100-continue`) shifts *when* the body is read, bypassing front-end sanitization. Kettle's "HTTP/1.1 must die" (2025) generalizes it; an HTTP/2-front-end + HTTP/1.1-upstream downgrade *amplifies* risk (a fourth way to declare length). 2025 cases: Cloudflare (~24M sites), Akamai CVE-2025-32094 (OPTIONS + obsolete line folding), Netlify, GitLab, AWS ALB+IIS; >$350K bounties.

**Detection:** Burp HTTP Request Smuggler's newer CL.0 / 0.CL / Expect probes, plus `CLZero` for CL.0 fuzzing. Confirm with the timing-delta-on-a-different-connection test — never your own follow-up request.

### Client-side / browser-powered desync (CSD) + pause-based desync (no shared back-end needed)
The above are **server-side** (front-end↔back-end disagreement, shared connection pool). The browser-powered class differs and is missed because it needs no proxy chain:
- **Client-side desync (CSD, PortSwigger 2022):** a single server mis-handles a request body (e.g., a `POST` to an endpoint that ignores the body — redirect/static/404), so the body stays in the socket and prepends to the *victim's own next request* — triggerable from JavaScript in the victim's browser via `fetch(...,{mode:'no-cors'})` over a reused connection. Impact = same-site request hijack / stored-XSS-equivalent / cred theft **without** a vulnerable front-end. Probe: a bodyless-handling endpoint that leaves the connection poisoned; confirm in Burp with the "connection-state" attack mode.
- **Pause-based desync (2022/2025):** send headers, **pause**, and time the server's read — servers that read the body in a second TCP segment after a delay reveal a desync window even when single-packet probes look clean. Burp's "pause before sending body" / Turbo Intruder time-gating. Pairs with Expect-desync.
- **Connection-state attacks:** first-request-routing / first-request-validation — the front-end applies auth/routing only to the *first* request on a connection, so a smuggled/pipelined second request inherits it (reach internal vhosts / skip the WAF). Test by pipelining two requests on one keep-alive connection.

Sources: https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/ · https://portswigger.net/research/http1-must-die · https://portswigger.net/research/browser-powered-desync-attacks

### "HTTP/1.1 must die" — parser-discrepancy hunting (2025 research)

The 2025 generalization: stop testing *named* length-tricks (CL.TE/TE.CL) first and instead **map the parser boundary**, because any header the front-end sees but the back-end hides (or vice-versa) makes a desync class *latent* even after the specific length-trick of today is patched.

- **Parser-discrepancy scan (V-H / H-V) as the FIRST move.** Probe for a header one side *visibly* processes while the other *hides* it, using a partially-obscured header (leading space, a duplicate with an invalid value, obs-fold), and read the **response-code delta** (e.g. `200` vs `503`) to locate the boundary. A mismatch = a latent desync even if no CL/TE trick fires today. HTTP Request Smuggler **v3.0** automates this scan. Source: https://portswigger.net/research/http1-must-die
- **Single-connection "visible" desync (V-H / H-V without Transfer-Encoding).** WAFs now regex-block smuggled `Transfer-Encoding`; instead exploit generic parser-*visibility* gaps with a partially-obscured header and **no TE at all** — nothing for the TE signature to match. Source: https://portswigger.net/research/http1-must-die
- **Double-desync (0.CL → CL.0 chaining) — byte-offset weaponization.** (Extends the double-desync note above.) The first request uses **0.CL** to slice the header block off the *second* request, which is then re-weaponized as **CL.0** to re-poison with a malicious prefix. Because servers *append* rather than prepend headers, the offset is predictable — calculate exact byte offsets to cut the victim's headers mid-transmission → stable cross-user smuggling. Source: https://portswigger.net/research/http1-must-die
- **0.CL early-response gadgets (break the deadlock).** A 0.CL stalls because the back-end waits for a body that never arrives; break it by targeting an endpoint that **responds BEFORE reading the body**: reserved Windows/IIS device filenames (`/con`, `/nul`), server-level redirects, any early `301`/`400`. Without such a gadget the 0.CL is unexploitable — hunt one first. Source: https://portswigger.net/research/http1-must-die
- **Obfuscated `Expect` variants (`Expect: y 100-continue` and mutants).** Same broken 100-continue state machine as Expect-desync, but the value is mutated so the exact-string `100-continue` WAF signature never matches while the front-end parser still enters the confused state. Works in both 0.CL and CL.0. (Base case already noted above; these are the WAF-evading mutants.) Source: https://portswigger.net/research/http1-must-die
- **Expect-triggered dual response-header-block leak (info-leak, not splitting).** `Expect: 100-continue` makes some stacks emit **TWO** response header blocks; header-stripping proxies sanitize only the *first*, so internal headers (`X-Cache-Key`, account IDs, backend routing) leak in the *second*. Pure info-disclosure primitive. Source: https://portswigger.net/research/http1-must-die
- **CVE-2024-24791 — Go `net/http` ReverseProxy Expect connection-pool poisoning.** Repeated `Expect: 100-continue` to a Go `httputil.ReverseProxy` poisons upstream keep-alive pool connections (mishandled interim-response state) → DoS + desync against a ubiquitous proxy lib. Fingerprint the Go stack and fire. Source: https://www.sentinelone.com/vulnerability-database/cve-2024-24791/

### "Funky Chunks" — chunk-terminator / trailer-newline ambiguity desync (w4ke, Jun 2025)

A desync that fires **without any CL/TE confusion at all**, so defenses tuned only to CL.TE/TE.CL (and WAFs that regex the `Transfer-Encoding` value) don't see it. The disagreement is in how each side parses the **chunk framing itself**: chunk-size lines and the chunk/trailer section end in a two-byte `\r\n` terminator, and parsers differ on whether a lone `\r` or lone `\n` (or a stray newline in the trailer block) closes the chunk. A permissive parser **overreads** past what the strict side considers the message boundary — the overread bytes become the prefix of the next request on the connection. Both sides accept `Transfer-Encoding: chunked` (no dueling length headers), so it slips past CL.TE-only mitigations.

- **Probe:** send a chunked body where the chunk-size or trailer line uses a single-byte terminator (bare `\n`, or a trailer with an extra/mismatched newline) so one hop consumes an extra byte or an extra line the other doesn't; confirm with the timing-delta-on-a-different-connection test (never your own follow-up).
- **When to reach for it:** front-end is RFC-strict on CL/TE (Nginx/Envoy/Caddy in the matrix above) yet still forwards chunked bodies to origin — the framing ambiguity survives even where the classic length tricks are dead.
- Source: https://w4ke.info/2025/06/18/funky-chunks.html

### "Single-Packet Shovel" — desync-powered request tunnelling (Assured, 2025)

Combines the **single-packet attack** (all bytes in one TCP segment, the same primitive that powers single-packet race conditions) with an **H2→H1 downgrade desync** to *tunnel* a whole request past the front-end into internal-only paths — a front-end auth/routing **bypass** rather than a cross-user poison. The single-packet delivery removes network-jitter noise so the desync lands reliably; the tunnelled request reaches back-end vhosts/routes the edge WAF/ACL believes it filtered (extends the connection-state / first-request-routing note above).

- **Use it for:** reaching internal-only admin/routing paths behind an H2 front-end + H1 origin where a normal external request is blocked by the edge, and for making flaky downgrade-desyncs deterministic.
- **Tooling:** Turbo Intruder single-packet mode + Burp HTTP Request Smuggler H2-downgrade probes.
- Source: https://assured.se/posts/the-single-packet-shovel-desync-powered-request-tunnelling

---

## Related Skills & Chains

- **`hunt-cache-poison`** — Smuggling + cache is the canonical critical chain; one smuggled request becomes the cached response for every subsequent victim. Chain primitive: CL.TE smuggle a request whose response body contains attacker HTML/JS → front-end cache stores it under a popular URL (`/`, `/login`) → de-sync poisoning where the smuggled request becomes the cached response for the next N victims, persisting for the cache TTL.
- **`hunt-auth-bypass`** — Smuggling reaches internal-only routes that the front-end WAF/auth-proxy filters out. Chain primitive: smuggle `GET /admin/users HTTP/1.1` past the front-end ACL that blocks external `/admin/*` → backend processes the smuggled request as if from a trusted internal source → bypass front-end auth by smuggling internal-routed request → admin data in the response queue.
- **`hunt-idor`** — Smuggling attaches the NEXT user's session cookies to an attacker-controlled request path. Chain primitive: smuggle `GET /api/me HTTP/1.1` with no cookies → backend pairs it with the next legitimate user's incoming connection cookies → victim's session cookie attached to attacker's smuggled request → attacker reads the response containing victim's PII/tokens.
- **`hunt-xss`** — Smuggling injects XSS payloads into the response stream of the next victim without ever appearing in a URL parameter. Chain primitive: smuggled request body contains reflected payload that the backend renders into the next response in the queue → next visitor to `/` receives attacker HTML inline → reflected XSS at every visitor without any URL parameter visible to them or to logs.
- **`security-arsenal`** — Reach for the smuggling payload bank (CL.TE / TE.CL / TE.TE obfuscations, H2.CL downgrade probes, h2csmuggler one-liners, Burp HTTP Request Smuggler extension config) and the time-delay confirmation template before manual hex-editing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the smuggled-request effect MUST land on a request issued by a different client/session, not your own follow-up. A timing delta in your own browser alone is parser disagreement, not exploitable smuggling.


