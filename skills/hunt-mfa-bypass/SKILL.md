---
name: hunt-mfa-bypass
description: "Hunt MFA / 2FA bypass — 7 distinct patterns. (1) MFA not enforced on sensitive endpoints (password change, email change accept without MFA challenge), (2) MFA-step skip via direct navigation to post-login URL, (3) MFA-token replay (same code accepted twice), (4) brute-force the 6-digit OTP without rate limit (10^6 attempts at server speed), (5) race condition on OTP validation, (6) recovery-code dump via /api/me, (7) backup factor downgrade (SMS factor with no rate limit). Plus the chain: cookie theft + password oracle + no step-up = ATO without MFA challenge. Detection: trace auth flow in Burp, find every state transition, check if MFA is middleware-gated vs per-endpoint, check OTP entropy and rate limit on OTP-validate. Validate: attacker session reaching post-MFA state. Use when hunting auth bypass, MFA flows, chaining primitives toward ATO."
---

## 19. MFA / 2FA BYPASS
> Growing bug class — 7 distinct patterns. Pays High/Critical when it enables ATO without prior session.

### Pattern 1: No Rate Limit on OTP
```bash
# Test with ffuf — all 1M 6-digit codes
ffuf -u "https://target.com/api/verify-otp" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 -t 5
# -t 5 (slow down) — aggressive rates get 429 or ban
```

### Pattern 2: OTP Not Invalidated After Use
```
1. Login → receive OTP "123456" → enter it → success
2. Logout → login again with same credentials
3. Try OTP "123456" again
4. If accepted → OTP never invalidated = ATO (attacker sniffs OTP once, reuses forever)
```

### Pattern 3: Response Manipulation
```
1. Enter wrong OTP → capture response in Burp
2. Change {"success":false} → {"success":true} (or 401 → 200)
3. Forward → if app proceeds → client-side only MFA check
```

### Pattern 4: Skip MFA Step (Workflow Bypass)
```bash
# After entering password, app sets a "pre-mfa" cookie → redirects to /mfa
# Test: skip /mfa entirely, access /dashboard directly with pre-mfa cookie
# If app grants access without MFA = auth flow bypass = Critical
curl -s -b "session=PRE_MFA_SESSION" https://target.com/dashboard
```

### Pattern 5: Race on MFA Verification
```python
import asyncio, aiohttp

async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify",
                            json={"otp": otp}) as r:
        return r.status, await r.text()

async def race():
    cookies = {"session": "YOUR_SESSION"}
    async with aiohttp.ClientSession(cookies=cookies) as s:
        # Fire ~30 concurrent submissions of the SAME OTP to hit the TOCTOU
        # window before the server marks it used. Two requests are NOT enough —
        # they almost always resolve sequentially as "already-used" (false negative).
        # Best done as a single-packet / 20+ HTTP-2-stream attack (Turbo Intruder).
        results = await asyncio.gather(*[verify(s, "123456") for _ in range(30)])
        # Race confirmed if >1 success (or 1 success among many "already-used").
        for status, body in results:
            print(status, body)
asyncio.run(race())
```

### Pattern 6: Backup Code Brute Force
```
Backup codes: typically 8 alphanumeric = 36^8 = ~2.8T (too large)
BUT: check if backup codes are only 6-8 digits = 1-10M range = feasible with no rate limit
Also test: can backup codes be reused after exhaustion? Some apps regenerate predictably.
```

### Pattern 7: "Remember This Device" Trust Escalation
```
1. Complete MFA once on Device A (attacker's browser)
2. Capture the "remember device" cookie
3. Present that cookie from a new IP/browser
4. If MFA skipped = device trust not bound to IP/UA = ATO from any location
```

### Patterns 8–16: canonical long-tail (commonly missed — HackTricks 2FA-bypass / EmadYaY 2FA-Bypass-Techniques / PATT)
Fire ALL of these — they're the "no-signature" variants that don't show up in a quick pass:
```
[8]  RATE-LIMIT RESET via resend: brute the OTP, and every N tries RE-REQUEST a new code
     → if the resend resets the attempt counter, brute is effectively unlimited (the #1 reason a
     "rate-limited" OTP is still brute-forceable). Also: limit is per-code not per-account → new flow each round.
[9]  OTP NOT BOUND to account/session (CROSS-USER): request OTP as attacker-A, then submit A's
     valid code in VICTIM-B's verify request (swap the session/userId/flow-id). If accepted, the code
     isn't bound to identity → ATO. Also: your own 2FA code satisfying another account's challenge.
[10] 2FA-SKIPPING LOGIN PATHS (the big one): does OAuth/social login, a legacy /mobile or /v1 API
     login, SAML, or a magic-link return a full session WITHOUT the 2FA step? And does PASSWORD RESET
     log the user straight in (or clear 2FA) → reset = total 2FA bypass? Enumerate EVERY auth entry and
     check which actually enforce 2FA.
[11] DISABLE / ENABLE 2FA without re-auth: POST /disable-2fa with no current OTP/password (CSRF or
     IDOR on {userId}) → strip victim's 2FA. Or ENROLL attacker's authenticator onto the victim (bind
     your TOTP secret to their account) → you own their 2FA.
[12] OTP TYPE-CONFUSION / null / empty / boundary (apply the param-pollution matrix to the code):
     "", null, [], {"otp":["000000","real"]}, 000000, 00000000 (leading-zero/length), true, integer-vs-
     string, very-long, %00 — some validators accept empty/null/array or compare loosely.
[13] CODE / SECRET LEAKED in a response: the verify/setup/status/"resend" endpoint returns the OTP,
     the TOTP seed (generate codes yourself), or a 2fa_verified/required flag the client trusts.
[14] OLD CODE still valid after a new one is requested (no invalidation), and code valid across a
     LONGER window than stated (no/long expiry) — capture, wait, replay.
[15] STATUS/STEP flag forced: a separate endpoint or response field sets mfa_required=false /
     step=complete / 2fa_passed=true that the next request trusts (response-tamper twin of [3]).
[16] ACCOUNT-RECOVERY / backup-factor DOWNGRADE skips 2FA: "lost device" / SMS-fallback / security-
     question / support-recovery path that re-authenticates with a WEAKER factor and no 2FA.
```
**Confirm cross-user/skip findings with TWO accounts** (attacker A vs victim B): success = attacker session reaches a post-2FA state on B without ever entering B's code. Refs: HackTricks *2FA/MFA/OTP Bypass*, github.com/EmadYaY/2FA-Bypass-Techniques, PayloadsAllTheThings.

### MFA Chain Escalation
```
Rate limit bypass + no lockout = ATO (Critical)
Response manipulation = client-side only check = Critical
Skip MFA step = auth flow bypass = Critical
OTP reuse = persistent session hijack = High
```

---

## Recent MFA-bypass research (2024-2026)

### Pattern 17: WebAuthn / passkey downgrade via spoofed unsupported client
An AitM proxy spoofs an unsupported browser/OS (e.g. Safari-on-Windows) so the IdP (demonstrated on Entra ID) DISABLES passkeys and offers a weaker phishable fallback (SMS/OTP/password), which the proxy then relays. No crypto break — it abuses uneven WebAuthn UA support + the IdP's fallback policy.
```
1. Victim's IdP offers passkey (phishing-resistant) as primary factor.
2. AitM proxy rewrites the User-Agent / navigator to an OS/browser combo the IdP
   treats as passkey-unsupported (or force navigator.credentials.get() to fail).
3. IdP falls back to SMS/OTP/password → phishable → proxy relays it → session steal.
Test: does altering UA or failing the WebAuthn ceremony force a weaker method,
      or does the IdP hard-fail? A silent downgrade to a phishable factor = finding.
```
Source: https://thehackernews.com/2025/10/how-attackers-bypass-synced-passkeys.html

### Pattern 18: FIDO2 hybrid-transport (QR/cross-device) relay — "PoisonSeed"
The WebAuthn **hybrid transport** (the cross-device "scan this QR with your phone" flow) is NOT origin-bound the way a local authenticator is — the QR/BLE handshake proves possession of a passkey but does not bind it to the *browser that is logging in*. An AitM phishing page renders the *IdP's real* login, the victim scans the QR with their phone, and the passkey ceremony completes **for the attacker's session** because the relying party only sees a valid assertion, not which device initiated it.
```
1. Attacker starts a login to the real IdP → IdP returns a hybrid-flow QR.
2. Attacker proxies that QR onto the phishing page ("sign in with your phone").
3. Victim scans with their phone, approves the passkey prompt (looks legitimate).
4. Assertion satisfies the RP → attacker's session is now authenticated. No crypto break.
Test: does the RP offer hybrid/cross-device sign-in, and is a QR/BLE assertion
      accepted from a session on a different network/device than the authenticator?
```
Source: https://www.expel.com/blog/poisonseed-downgrading-fido-key/

### Pattern 19: WebAuthn credential-binding gap — assertion accepted for the wrong user (CVE-2025-26788)
Some RPs verify the WebAuthn assertion signature but fail to bind the returned **credential ID** to the account being logged into — so an attacker registers a passkey on *their own* account, then replays that assertion during a login attempt for a *victim* account (or swaps the `userHandle`/`credentialId` in the finish-auth request). The server validates the signature (valid) but never checks the credential belongs to the claimed user → auth as anyone.
```
Test the finish-authentication request: swap credentialId / userHandle / rawId to values
from an attacker-registered passkey while asserting the victim's username. If it authenticates,
the credential↔account binding is missing. Also test: passkey registered on account A usable to
log into account B; assertion for a deleted/other credential accepted.
```
Source: https://nvd.nist.gov/vuln/detail/CVE-2025-26788

---

## Related Skills & Chains

- **`hunt-ato`** — MFA bypass is a primitive; ATO is the destination. Chain primitive: cookie theft (via XSS or session-fixation) + password oracle (login response timing/length diff reveals valid passwords without lockout) + no MFA step-up on password-change endpoint = persistent ATO without ever facing the OTP challenge → password rotated, attacker locks victim out.
- **`hunt-race-condition`** — Pattern 5 (OTP race) lives in race-condition territory; load both skills together. Chain primitive: same 6-digit OTP submitted via 20 parallel HTTP/2 streams (single-packet Turbo Intruder attack) before the server marks it used → 1 success + 19 "already-used" → race window confirmed → attacker doesn't need to brute, just guesses once and parallelizes → ATO.
- **`hunt-auth-bypass`** — MFA-step-skip is auth-flow bypass at the workflow layer. Chain primitive: pre-MFA cookie issued after password step + direct navigation to `/dashboard` skipping `/mfa` route + server only middleware-gates `/mfa` not `/dashboard` = full post-auth access from password-only state → MFA never enforced because the route gate was misplaced.
- **`hunt-misc`** — Recovery-code dump via `/api/me` is a misc-class info disclosure that becomes Critical when chained. Chain primitive: `/api/me` returns full user object including `backup_codes` array (plaintext, never rotated) → attacker with any read-IDOR or XSS exfils backup codes → uses one backup code → MFA satisfied → ATO without OTP knowledge.
- **`security-arsenal`** — Pull the OTP-brute-force payload section (000000-999999 wordlist generator, ffuf rate-limit-evasion patterns with `-t 5 -p 0.5-2`, distributed-IP rotation via proxychains) and the JWT-token-replay table when "MFA satisfied" claim lives in a JWT claim that can be forged.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an MFA bypass that only works when the attacker already has the password. Standalone MFA bypass is High; chained-with-password-oracle is Critical; chained-with-cookie-theft-only is Critical. The chain question separates the two.

