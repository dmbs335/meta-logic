# Cookie Specification Security Analysis

> **Analysis Target**: RFC 6265 (HTTP State Management), RFC 6265bis (Cookies Update)
> **Methodology**: Spec extraction + CVE/attack research cross-mapping
> **Latest Cases**: CVE-2025-27794 (Flarum), CVE-2024-53704 (SonicWall), CVE-2024-21583 (GitPod), C4 Bomb (CyberArk 2024)
> **Date**: February 2026

---

## Executive Summary

Cookies are bearer credentials with no built-in integrity, confidentiality, or revocation. Core attack surfaces: (1) **subdomain injection** (cookie tossing) via domain attribute inheritance, (2) **attribute bypass** (SameSite method override, HttpOnly sandwich, Secure downgrade), (3) **session management gaps** (fixation, Pass-the-Cookie MFA bypass), (4) **parser inconsistencies** (duplicate names, quoted values, prefix bypass). 22 vulnerability classes mapped to RFC sections. USENIX Security 2023 "Cookie Crumbles" found 9/13 major frameworks vulnerable to cookie integrity attacks.

---

## Part I: Cookie Scoping Vulnerabilities

### 1. Cookie Tossing — Subdomain Injection (RFC 6265 §5.1.3)

Domain attribute allows subdomain inheritance. Attacker controlling `evil.example.com` sets `session_id=attacker_value; Domain=.example.com` → victim visits `example.com` → both cookies sent. RFC 6265 does not specify duplicate name handling (first vs last vs concatenate → unpredictable).

**CVEs**: CVE-2024-21583 (GitPod session fixation), OAuth flow hijacking (Snyk Labs 2024), Self-XSS escalation via cookie tossing (Thomas Houhou 2024 — Swisscom, Jupyter, Perplexity AI).

**Defense**: `__Host-` prefix (RFC 6265bis §4.1.3.1) — enforces Secure, Path=/, no Domain. `__Secure-` prefix requires Secure attribute.

### 2. Cookie Prefix Bypass — UTF-8 Encoding (PortSwigger Research)

Browser prefix checker operates on raw bytes before URL decoding. `__%48ost-session` ≠ `__Host-session` (prefix check passes) → application URL-decodes `%48` to `H` → reads as `__Host-session`. Affected: Chromium-based browsers.

**Defense**: Application-level prefix validation after URL decoding.

### 3. Path-Based Cookie Shadowing (RFC 6265 §5.1.4)

Attacker sets `admin_token=fake; Path=/` from `/public` → shadows legitimate `admin_token=secret; Path=/admin`. USENIX 2023 identified path attacks across 9/13 frameworks (Symfony, CodeIgniter 4, Fastify).

**Defense**: Avoid path-based security boundaries. Use `__Host-` prefix.

### 4. Cookie Jar Overflow (IBM PTC Security, IRON CTF 2024)

Browser limits: Chrome 180, Firefox 150, Safari 600 cookies per domain. FIFO eviction deletes oldest first. HttpOnly cookies (set by server, typically oldest) deleted first → attacker fills jar via XSS → forces HttpOnly cookie deletion → sets replacement without HttpOnly → HttpOnly protection bypassed.

**Defense**: Cookie count monitoring (reject >50), `__Host-` prefix, CSP.

---

## Part II: Cookie Security Attributes

### 5. Secure Attribute Bypass (RFC 6265 §5.4)

Prevents HTTPS→HTTP leakage but NOT HTTP→HTTPS overwriting. Network attacker injects `session_id=attacker_value` over HTTP → next HTTPS request sends both cookies → session fixation if server uses first cookie.

**Defense**: `__Secure-` prefix, HSTS with includeSubDomains.

### 6. HttpOnly Bypass Techniques (RFC 6265 §8.5)

Prevents `document.cookie` read but NOT cookie use in requests (`fetch` with `credentials: 'include'`). **Cookie Sandwich** (PortSwigger): delimiter cookies wrap HttpOnly value → vulnerable servers reflect it. **Browser extensions**: `chrome.cookies.getAll()` bypasses HttpOnly entirely.

### 7. SameSite Bypass Vectors (RFC 6265bis §5.3.7)

Values: Strict (same-site only), Lax (+ top-level GET), None (all, requires Secure). Chrome/Edge default to Lax; Safari defaults to None.

**Bypasses**: (1) **Method override** — `GET /change-email?_method=POST` → Lax sends cookies, server processes as POST (Express, Laravel, Rails, Django). (2) **2-minute Lax exception** — newly created cookies sent with ALL requests for 2 minutes (Premsai 2025). (3) **Sibling subdomain** — requests from `sub.example.com` to `example.com` are same-site → SameSite=Strict cookies sent → XSS on any subdomain enables CSRF. (4) **Android Intent scheme** — Chrome treated `intent://` as same-site (fixed 2023).

**Defense**: POST for state changes, CSRF tokens always, check session age for critical ops.

---

## Part III: Session Management Attacks

### 8. Session Fixation (USENIX Security 2023)

RFC 6265 doesn't address session lifecycle. Cookie tossing or network injection forces attacker-controlled session ID → if app doesn't regenerate after login → attacker hijacks authenticated session.

**CVEs**: CVE-2024-24823 (Graylog), CVE-2024-38513 (GoFiber — missing `sess.Regenerate()`). USENIX 2023: Symfony MIGRATE didn't clear CSRF storage, Fastify and CodeIgniter 4 Shield vulnerable.

**Defense**: Regenerate session ID after authentication + privilege escalation. `__Host-` prefix.

### 9. Pass-the-Cookie — MFA Bypass (Netwrix, MixMode Cookie-Bite)

Cookies represent post-authentication state → replaying stolen cookies bypasses MFA entirely. **Cookie-Bite**: targets Azure `ESTSAUTH` cookie (24h validity) → access to all Azure-integrated services without MFA. Invisible to SOC (no failed login attempts).

Theft vectors: Infostealer malware (Lumma, StealC, RedLine) extracts cookies via Windows DPAPI, browser extensions with `cookies` permission, network sniffing. **Cyberhaven supply chain attack** (Dec 2024): phished developer → malicious extension update → 2.6M users → 12h window.

**Defense**: Token lifetime ≤1h, device-based conditional access, Azure CAE, DBSC (see §12).

### 10. CSRF/CORF (RFC 6265 §8.8)

Cookies auto-attached → cross-site request forgery. **CORF** (USENIX 2023): SameSite checks site, not origin → XSS on sibling subdomain enables cross-origin forgery with SameSite=Strict cookies.

**Defense**: SameSite (prevents cross-site, not CORF). Synchronizer token pattern (prevents both). Do NOT use double submit cookie pattern (vulnerable to cookie tossing per USENIX 2023).

### 11. Cookie Bomb DoS (HackerOne #57356, #221041)

Inject 100×4KB cookies via subdomain/XSS → server returns `431 Request Header Fields Too Large` → user-specific DoS.

---

## Part IV: Cookie Theft & Device Binding

### 12. C4 Bomb — Chrome Cookie Cipher Cracker (CyberArk 2024)

Chrome 127+ introduced Application-Bound Encryption (Windows DPAPI). CyberArk found padding oracle attack against AES-CBC → low-privileged attacker recovers plaintext cookies byte-by-byte without Administrator. Disclosed Dec 2024 → partial fix Jun 2025.

### 13. Infostealer Cookie Theft

Lumma Stealer bypassed Chrome App-Bound Encryption within 24 hours (Sep 2024) by injecting into Chrome process. Cat-and-mouse continues. Stolen cookies enable Pass-the-Cookie attacks (§9).

### 14. Device Bound Session Credentials — DBSC (Chrome for Developers)

Cryptographically binds sessions to TPM hardware. Browser generates asymmetric keypair (private key in TPM) → server associates session with public key → each request signed → replay from different device fails. Defeats infostealer, extension theft, and network MitM.

**Status**: Chrome 131+ Beta, Windows 11 + TPM 2.0 only. No cross-device portability.

---

## Part V: Parser Inconsistencies

### 15. Phantom $Version Cookie (PortSwigger)

Legacy RFC 2109 `$Version` attribute (deprecated in RFC 6265). Some WAFs skip parsing after `$Version` → payload bypass.

### 16. Cookie Injection via Special Characters (PortSwigger)

`document.cookie = "username=" + userData` where userData contains `;admin=true` → browser interprets as two cookies. CRLF injection enables header injection in some implementations.

**Defense**: Whitelist characters, `encodeURIComponent()`.

---

## Part VI: Third-Party Cookie Deprecation

Chrome abandoned forced deprecation (Jul 2024) → user opt-in. Safari blocks all, Firefox blocks known trackers. ~70% users still have third-party cookies enabled (2026). **CHIPS** (Partitioned cookies): `Partitioned` attribute isolates cookies per top-level site. **Storage Access API**: explicit user permission for third-party cookie access.

---

## CVE Summary (2024-2025)

| CVE | Target | Type | Severity |
|-----|--------|------|----------|
| CVE-2025-27794 | Flarum | Session hijacking (unsigned cookie data) | Critical (9.1) |
| CVE-2024-53704 | SonicWall SSL VPN | Predictable IV → auth bypass | Critical (9.8) |
| CVE-2024-21583 | GitPod | Cookie tossing → session fixation | High |
| CVE-2024-24823 | Graylog | Session fixation via cookie injection | High |
| CVE-2024-52804 | Tornado | Cookie parsing ReDoS | High (7.5) |
| CVE-2024-38513 | GoFiber | Missing session regeneration | High (7.3) |
| CVE-2024-56733 | Password Pusher | Predictable token generation | Medium (6.5) |

---

## Attack-Spec-Defense Mapping

| Attack | Spec Reference | Defense |
|--------|---------------|---------|
| Cookie Tossing | RFC 6265 §5.1.3 (domain inheritance) | `__Host-` prefix |
| UTF-8 Prefix Bypass | RFC 6265bis §4.1.3 | App-level validation post-decode |
| Path Shadowing | RFC 6265 §5.1.4 | Avoid path-based security |
| Cookie Jar Overflow | RFC 6265 §6.1 (FIFO eviction) | Count monitoring + `__Host-` |
| Secure Downgrade | RFC 6265 §5.4 | `__Secure-` prefix + HSTS |
| HttpOnly Bypass | RFC 6265 §8.5 | Cookie Sandwich: strict parsing |
| SameSite Bypass | RFC 6265bis §5.3.7 | POST for state changes + CSRF tokens |
| Session Fixation | N/A (spec doesn't cover sessions) | Regenerate ID after auth |
| Pass-the-Cookie | N/A (static credentials) | DBSC (TPM binding) + short TTL |
| CSRF/CORF | RFC 6265 §8.8 | SameSite + synchronizer tokens |
| Cookie Bomb | RFC 6265 §6.1 | Server-side size/count limits |
| Cookie Parsing Injection | RFC 6265 §4.2 | Input validation/sanitization |

---

## Sources

**Specs**: [RFC 6265](https://datatracker.ietf.org/doc/html/rfc6265) | [RFC 6265bis](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html)

**Research**: [USENIX 2023 "Cookie Crumbles"](https://www.usenix.org/conference/usenixsecurity23) | [PortSwigger Cookie Chaos](https://portswigger.net/research) | [CyberArk C4 Bomb](https://www.cyberark.com/) | [Snyk Cookie Tossing](https://snyk.io/blog/) | [Chrome DBSC](https://developer.chrome.com/) | [MixMode Cookie-Bite](https://mixmode.ai/)

**CVEs**: [CVE-2025-27794 (Flarum)](https://www.cve.org/CVERecord?id=CVE-2025-27794) | [CVE-2024-53704 (SonicWall)](https://www.cve.org/CVERecord?id=CVE-2024-53704) | [CVE-2024-21583 (GitPod)](https://www.cve.org/CVERecord?id=CVE-2024-21583) | [CVE-2024-52804 (Tornado)](https://www.cve.org/CVERecord?id=CVE-2024-52804)
