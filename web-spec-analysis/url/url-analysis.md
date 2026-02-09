# URL Specification Security Analysis: Direct Extraction from RFC/Spec Sources

> **Analysis Target**: RFC 3986 (URI Generic Syntax), WHATWG URL Living Standard
> **Methodology**: Direct spec examination + cross-analysis with CVEs and attack cases
> **Coverage**: CVEs and conference presentations from 2024-2025
> **Date**: 2026-02-08

---

## Executive Summary

This analysis covers **29 security issues** in URL parsing, organized into four parts: meta-level design issues, parser differentials, normalization security, and CVE case studies. The fundamental problem: **the same URL string can be interpreted differently by different parsers** due to RFC 3986 vs WHATWG spec conflicts, implementation inconsistencies, and normalization ambiguities. This creates systemic SSRF, open redirect, and authentication bypass attack surfaces.

---

## Part 1: Meta-level Design Issues in URL Parsing

### 1. RFC 3986 vs WHATWG Spec Conflict

RFC 3986 requires scheme; WHATWG allows relative URLs and removes tabs/newlines. Same URL → different parser interpretations → **SSRF bypass** when validation layer (RFC parser) and request layer (urllib3) disagree.

**CVEs**: CVE-2024-22259, CVE-2024-22243, CVE-2024-22262 (Spring `UriComponentsBuilder` host validation bypass → SSRF/Open Redirect). Snyk (2024): 5 inconsistency classes among 16 parsers.

**Defense**: Use same parser for validation and execution. Allow absolute URIs only for external input.

### 2. Userinfo Field Vulnerabilities (RFC 3986 §7.5)

`user:password@host` syntax is deprecated but grammatically valid. Enables domain spoofing: `https://trusted-bank.com:fakepass@evil.com/phishing` — users see `trusted-bank.com` but connect to `evil.com`. Credentials also leak in logs/history.

Chrome, Firefox, Safari now reject/remove userinfo. WHATWG §4.4 prohibits it entirely. **Defense**: Reject URLs containing userinfo.

### 3. Percent-Encoding Duality (RFC 3986 §2.1)

RFC 3986 §2.4: *"Implementations MUST NOT percent-encode or decode the same string more than once."* But many implementations recursively decode:

- `%252e%252e%252f` → 1st decode: `%2e%2e%2f` → 2nd decode: `../` → path traversal
- `/%2e%2e%2f` bypasses WAF string matching for `../`

**CVEs**: CVE-2021-41773 (Apache path traversal via `%2e`), Axios SSRF (#7315, `https:google.com` auto-normalized), ChatGPT account takeover (2023, path normalization).

**Defense**: Decode exactly once on input. Normalize before validation. Check path traversal after decoding.

### 4. Authority Component Ambiguity (RFC 3986 §3.2)

Slash count and backslash handling differ across parsers:
- `https:/evil.com` (one slash): strict parsers error, lenient parsers parse host
- `https:\\evil.com`: Windows parsers convert `\` to `/`, Unix parsers treat `\` as regular character

**CVEs**: CVE-2024-38473, CVE-2024-38476, CVE-2024-38477 (Orange Tsai, Black Hat 2024: Apache Confusion Attacks — filename/DocumentRoot/handler confusion, backslash → NTLM relay → RCE).

**Defense**: Strictly validate slash count. Don't auto-convert backslashes. Distinguish filesystem paths from URLs.

### 5. Legacy IP Address Notation (RFC 3986 §7.4)

SSRF filter bypass via alternative notations — all resolve to 127.0.0.1:
- Octal: `http://0177.0.0.1`
- Hex: `http://0x7f.0.0.1`
- Integer: `http://2130706433`
- Mixed: `http://0177.0x00.0.01`

**Defense**: Normalize all IP formats before validation. Use `inet_pton` instead of regex. Check internal ranges on normalized form.

### 6. Fragment Identifiers — Client-Side Only (RFC 3986 §3.5)

Fragments not sent to server → WAF bypassed. Client-side JavaScript processing enables XSS: `/#<script>alert(1)</script>`. OAuth Implicit Flow token leak via `location.hash`.

**Defense**: Validate fragment-based routing inputs. Never include tokens in fragments. Use Authorization Code + PKCE instead of Implicit Flow.

---

## Part 2: Parser Differentials Between Implementations

### 7. Scheme Requirement Differences

RFC 3986 requires scheme, WHATWG allows relative URLs. `//evil.com/payload`: strict parser errors, lenient infers `http://`, relative parser resolves against base.

**Defense**: External inputs must use absolute URIs with explicit scheme.

### 8. Host Extraction Inconsistencies (`getHost()` Problem)

Each language returns different results for edge cases:
```java
// Java: "http://example.com@evil.com/" → getHost() varies by implementation
// Python: "http://127.%30.%30.1/" → urlparse preserves encoding, requests decodes
```

**CVEs**: Spring CVE-2024-22259 (UriComponentsBuilder vs HTTP client differential), Log4j CVE-2021-44228 (JNDI URL parsing).

**Defense**: Don't trust `getHost()`. Use explicit RFC 3986 parser. Re-validate after IP conversion. Allow-list, not deny-list.

### 9. URL Encoding Processing Inconsistencies

Parsers vary in decoding timing (before/after validation), recursion (once/repeatedly), and case sensitivity (`%2E` vs `%2e`).

**Defense**: Decode exactly once → normalize → validate. RFC 3986 §2.4 MUST rule.

### 10. Backslash/Slash Confusion

RFC 3986 treats `\` as regular character. WHATWG normalizes `\` to `/` for http/https. Cross-platform differential enables SSRF.

**CVEs**: CVE-2024-38473 (Apache backslash → UNC path → NTLM relay → RCE).

**Defense**: Reject URLs containing backslashes or establish explicit normalization policy.

### 11. Tab/Newline Character Processing

WHATWG removes tabs/newlines to continue parsing. RFC 3986 requires percent-encoding. `http://tru\nsted.com@evil.com/` — filter sees `trusted.com`, browser removes `\n` → userinfo=`trusted.com`, host=`evil.com`.

**CVEs**: PortSwigger Black Hat 2024: Cache Key Confusion via tab/newline removal on Nginx/Cloudflare, Apache/CloudFront.

**Defense**: Reject URLs containing control characters (don't auto-remove).

---

## Part 3: Normalization and Comparison Security

### 12. Case Normalization Scope (RFC 3986 §6.2.2.1)

Scheme and host are case-insensitive (normalize to lowercase). Path is case-sensitive. Misapplying scope enables bypass: `/Admin` passes case-insensitive filter but case-sensitive server serves `/Admin` ≠ `/admin`.

**Defense**: Match validation case sensitivity to server behavior. Windows: lowercase paths. Unix: preserve case.

### 13. Percent-Encoding Normalization (RFC 3986 §6.2.2.2)

`/api/users` ≡ `/api/%75sers` (unreserved characters). Non-normalized URLs create duplicate cache entries and ACL bypass.

**CVEs**: PortSwigger Black Hat 2024 Cache Key Confusion, CVE-2021-41773.

**Defense**: Normalize on input (decode unreserved). Use normalized form for cache keys, ACLs, storage.

### 14. Path Segment Normalization (RFC 3986 §6.2.2.3)

`remove_dot_segments` algorithm removes `.` and `..`. Security depends on normalization ordering: Decode → Normalize → Validate (correct). Normalize → Decode (wrong — encoded `../` bypasses normalization).

**CVEs**: CVE-2021-41773, CVE-2021-42013 (Apache 2.4.49/2.4.50 path normalization regression).

**Defense**: Strictly follow Decode → Normalize → Validate order. Verify path stays inside DocumentRoot. Consider symlinks (`realpath()`).

### 15. Default Port Omission (RFC 3986 §6.2.3)

`http://example.com:80/` ≡ `http://example.com/`. Port inclusion/omission creates allow-list bypass, CORS policy inconsistency, cache key duplication.

**Defense**: Remove default ports during normalization. Store policies in normalized form.

### 16. Trailing Dot in Domain

WHATWG treats `example.com` ≠ `example.com.`. DNS trailing dot = FQDN. Inconsistency enables CORS bypass, cookie isolation bypass, DNS rebinding.

**Defense**: Remove or reject trailing dots. Base policies on normalized domains.

### 17. Unicode/IDN Homograph Attacks (RFC 3987)

Cyrillic `а` (U+0430) visually identical to Latin `a` (U+0061). `exаmple.com` → Punycode `xn--exmple-7fd.com`. Zero-width characters and Unicode normalization can also bypass filters.

**Defense**: Convert to Punycode before validation. Block mixed-script domains. Remove invisible characters.

---

## Part 4: CVE and Attack Case Studies

### 18. Spring Framework URL Parsing (CVE-2024-22259/22243/22262)

`UriComponentsBuilder.fromUriString()` and actual HTTP clients parse differently → validation passes but request goes to attacker host. Affected Spring 5.3.0-5.3.32, 6.0.0-6.0.17, 6.1.0-6.1.4.

### 19. SharePoint XXE (CVE-2024-30043)

URL parsing confusion between XML parser and URL validator → XXE injection → file reading + SSRF with Farm Service account privileges.

### 20. Apache Confusion Attacks (CVE-2024-38473/38476/38477)

Orange Tsai, Black Hat 2024: 3 confusion types (filename, DocumentRoot, handler), 9 vulnerabilities, 20 exploitation techniques. Backslash → UNC path → NTLM relay → RCE. Patched in Apache 2.4.60.

### 21. Axios SSRF (#7315)

`https:google.com` (missing slashes) auto-normalized to `https://google.com` → bypasses SSRF filters checking for `://`.

### 22. Apache Path Traversal (CVE-2021-41773, CVE-2021-42013)

Apache 2.4.49 path normalization change: `/.%2e/` not normalized → path traversal. 2.4.50 fix incomplete (CVE-2021-42013). Fixed in 2.4.51.

### 23. AutoGPT SSRF (CVE-2025-0454)

`http://localhost:\@google.com/../` — urlparse hostname confusion (includes colon) vs requests library (different interpretation) → SSRF bypass. CVSS 7.5.

### 24. mod_auth_openidc Open Redirect (CVE-2021-39191/32786)

`/\tevil.com` — validation sees relative path starting with `/`, browser parses as absolute URL → redirect to evil.com. Fixed in mod_auth_openidc 2.4.9.

### 25. parse-url Library SSRF (CVE-2022-2216/2900)

`http://127.0.0.1#@attacker.com/` — fragment/authority confusion → library reports wrong host → SSRF to localhost.

### 26. OAuth "Evil Slash" Attacks (Black Hat Asia 2019)

URL parsing inconsistencies bypass redirect_uri validation: `https://trusted.com\@evil.com`, `//evil.com`, `trusted.com@evil.com`. Study of 50 OAuth providers, 10K+ apps, tens of millions of users affected.

**Defense**: Exact string match for redirect_uri (not prefix/contains).

### 27. TOCTOU / DNS Rebinding

Time gap between DNS validation and HTTP request. Attacker changes DNS record (short TTL): validation → 1.2.3.4 (external, pass) → request → 127.0.0.1 (internal, SSRF).

**Defense**: Pin resolved IP, disable redirects, re-validate before request, atomic validation+request.

### 28. "yoU aRe a Liar" Framework (IEEE SPW 2022)

Cross-tested 1,445 URLs against 8 parsers (cURL, Chromium, Python, Java, Node.js, Go, Ruby, whatwg-url). Found **4,262 inconsistencies**, 56% affecting Same-Origin Policy.

### 29. Claroty/Snyk Industrial Systems Research (2022-2023)

5 confusion classes across 16 URL parsers. 8 vulnerabilities disclosed. OT/ICS systems particularly vulnerable due to legacy parsers and safety-critical impact.

---

## Appendix: Attack-Spec-Defense Mapping

| Attack | Spec Reference | Defense |
|--------|---------------|---------|
| Scheme Confusion | RFC 3986 §3 vs WHATWG §4.1 | Absolute URIs only, same parser |
| Userinfo Spoofing | RFC 3986 §3.2.1, §7.5 | Reject URLs with userinfo |
| Recursive Decoding | RFC 3986 §2.4 MUST | Decode exactly once |
| Backslash Confusion | RFC 3986 (unspecified) vs WHATWG | Reject backslashes |
| IP Obfuscation | RFC 3986 §7.4 | Normalize all formats, use `inet_pton` |
| Fragment XSS | RFC 3986 §3.5 | Validate fragment routing, CSP |
| Host Extraction | Implementation differences | Explicit RFC 3986 parsing, allow-list |
| Tab/Newline Bypass | WHATWG §4.1 auto-removal | Reject control characters |
| Path Traversal | RFC 3986 §6.2.2.3 | Decode → Normalize → Validate order |
| IDN Homograph | RFC 3987, WHATWG §3.3 | Punycode conversion, block mixed-script |
| Parser Differential SSRF | Implementation inconsistencies | Same parser for validation+request |
| TOCTOU DNS Rebinding | No spec for validation timing | Pin IP, disable redirects |
| OAuth Evil Slash | WHATWG vs RFC 3986 | Exact string match for redirect_uri |
| Cache Key Confusion | RFC 3986 §6.2.2 | Normalized URLs for cache keys |
| Default Port Bypass | RFC 3986 §6.2.3 | Remove default ports in normalization |

---

## Security Validation Checklist

**Input**: (1) Enforce absolute URI with scheme. (2) Reject userinfo. (3) Reject control chars (tab, newline, NULL). (4) Reject backslashes.

**Normalization**: (5) Percent-decode once only. (6) Decode unreserved chars. (7) Lowercase scheme/host only. (8) Apply `remove_dot_segments`. (9) Remove default ports. (10) Handle trailing dots. (11) Convert IDN to Punycode.

**Validation**: (12) Normalize all IP formats. (13) Allow-list scheme+host+port. (14) Block internal IPs. (15) Verify path inside allowed directory. (16) Resolve symlinks.

**Execution**: (17) Same parser for validation and request. (18) Never re-parse after validation. (19) Restrict/validate redirects. (20) Set connection timeouts.

---

## References

**Specs**: [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html) | [WHATWG URL](https://url.spec.whatwg.org/) | [RFC 3987 (IRI)](https://www.rfc-editor.org/rfc/rfc3987.html)

**Research**: [Orange Tsai — Apache Confusion Attacks (Black Hat 2024)](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/) | [PortSwigger URL Bypass Cheat Sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet) | [Snyk URL Confusion](https://snyk.io/blog/url-confusion-vulnerabilities/) | [Claroty URL Parsing](https://claroty.com/team82/research/exploiting-url-parsing-confusion) | [yoU aRe a Liar (IEEE SPW 2022)](https://secweb.work/papers/2022/ajmani2022youare.pdf)

**CVEs**: [CVE-2024-22259 (Spring)](https://spring.io/security/cve-2024-22259/) | [CVE-2024-30043 (SharePoint)](https://www.thezdi.com/blog/2024/5/29/cve-2024-30043-abusing-url-parsing-confusion-to-exploit-xxe-on-sharepoint-server-and-cloud) | [CVE-2021-41773 (Apache)](https://www.hackthebox.com/blog/cve-2021-41773-explained) | [CVE-2025-0454 (AutoGPT)](https://nvd.nist.gov/vuln/detail/CVE-2025-0454) | [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
