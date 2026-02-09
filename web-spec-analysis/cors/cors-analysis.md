# CORS Security Analysis

> **Analysis Target**: WHATWG Fetch Standard, RFC 6454 (Web Origin Concept)
> **Methodology**: Spec extraction + CVE/attack research cross-mapping
> **Latest Cases**: CVE-2024-25124 (Fiber), CVE-2024-8183 (Prefect), CVE-2025-5320 (Gradio), CVE-2025-57755 (Claude Code Router)
> **Date**: February 2026

---

## Executive Summary

CORS extends SOP by enabling controlled cross-origin relaxation. Key attack surfaces: (1) attacker-controlled `Origin` header drives server decisions (reflection vulnerability), (2) credential handling complexity creates exploitation pathways, (3) spec flexibility leads to regex bypass and parsing inconsistencies, (4) preflight cache poisoning bypasses checks, (5) subdomain/null origin trust boundary confusion. 12 vulnerability classes mapped to spec provisions.

---

## Part I: Architectural Foundations

### 1. Origin and Same-Origin Policy (RFC 6454)

Origin = `(scheme, host, port)` — identical in all three = same origin. RFC 6454 §8: *"The same-origin policy relies upon DNS for security"* — DNS poisoning subverts origin-based security entirely. IDNA migration can tear down security boundaries through browser inconsistencies in IDN handling.

### 2. Origin Header as Protocol Driver (WHATWG Fetch §3.2.5)

`Origin` header is client-supplied from attacker-controlled contexts. Spec doesn't mandate specific validation approaches. **Origin reflection** (echoing `Origin` in `Access-Control-Allow-Origin`) is the most common CORS misconfiguration.

**CVE-2024-8183** (Prefect): Reflected origins without validation → unauthorized data access.
**CVE-2024-25124** (Fiber): Allowed `*` + credentials through dynamic origin reflection.

### 3. Credential Handling — Wildcard Prohibition (WHATWG Fetch §3.2.3)

Browser enforces: `credentials: 'include'` cannot use `Access-Control-Allow-Origin: *`. Developers bypass via dynamic reflection without validation. Exploitation requires: reflected/permissive origin + `Allow-Credentials: true` + victim authenticated + sensitive endpoint.

### 4. Preflight Requests (WHATWG Fetch §4.10)

OPTIONS preflight for non-simple methods provides defense-in-depth. **Preflight cache poisoning** (CVE-2015-4520): non-credentialed preflight cached → credentialed actual request uses cached approval. Long `Access-Control-Max-Age` creates policy change enforcement gaps.

**Defense**: Keep max-age low (5-10 min), implement explicit OPTIONS handlers.

---

## Part II: Common Misconfiguration Attack Vectors

### 5. Null Origin Exploitation

Sandboxed iframes without `allow-same-origin` generate `Origin: null`. Whitelisting `null` for dev convenience → any website creates sandboxed iframe → steals authenticated data.

**Defense**: Never whitelist `null` in production.

### 6. Subdomain Trust Expansion

RFC 6454: subdomains are different origins. Wildcard subdomain whitelisting (`*.example.com`) creates transitive trust. XSS on any subdomain → CORS exploitation → data theft from API subdomain. Subdomain takeover (expired cloud services) provides legitimate origin. SameSite cookies bypassed because subdomains are "same-site."

**Defense**: Explicit individual subdomain whitelisting. CSP on all subdomains. DNS monitoring.

### 7. Regex Validation Bypass

No spec mandate for validation approach → developers use flawed regex. Common bypasses: missing anchors (`/trusted\.com/` matches `trusted.com.evil.com`), unescaped dots, prefix matching (`startsWith`/`includes`), underscore handling.

**Defense**: Explicit string matching preferred. If regex needed: `^https:\/\/([a-z0-9-]+\.)?example\.com$`. Or use URL parsing for validation.

### 8. Protocol Downgrade (RFC 6454 §8.4)

HTTP and HTTPS are different origins by design. Accepting both enables MITM: attacker intercepts HTTP page → injects JS → CORS request to HTTPS API accepted → data stolen through MITM'd HTTP channel.

**Defense**: Never whitelist HTTP origins for HTTPS resources. HSTS. `upgrade-insecure-requests`.

---

## Part III: Advanced Attack Techniques

### 9. Vary Header Absence — Cache Poisoning

Dynamic `Access-Control-Allow-Origin` without `Vary: Origin` → CDN caches one origin's CORS response → serves to all origins. Enables targeted DoS (poison with disallowed origin → legitimate users get CORS errors) or web cache deception.

**Defense**: Always `Vary: Origin` with dynamic ACAO. `Cache-Control: no-store` for sensitive endpoints.

### 10. Private Network Access (WICG PNA)

Pre-PNA: public websites can CORS-attack internal network resources (routers, IoT, internal APIs). PNA adds cross-network preflight with `Access-Control-Request-Private-Network: true`. **Currently on hold** — enforcement delayed, Chrome developing "Local Network Access" permission prompt for Chrome 142. Most internal devices don't implement PNA headers.

**Defense**: Internal services should not enable CORS for public origins. Require authentication even on internal networks. Firewall rules blocking RFC 1918 from public traffic.

### 11. SameSite Cookie Interaction

| SameSite | Cross-Origin Fetch | CORS Impact |
|----------|-------------------|-------------|
| Strict | Cookie NOT sent | CORS cannot bypass |
| Lax | Sent in top-level GET | CORS GET includes cookies |
| None; Secure | Sent in all contexts | CORS fully functional |

Subdomain XSS bypasses even `SameSite=Strict` (subdomains = same-site for cookies). CORS requiring credentials forces `SameSite=None` → sole protection is origin validation. Chrome's Lax+POST 2-minute grace period creates timing window.

### 12. Timing Side Channels (WHATWG Fetch §4.9)

Opaque responses (`no-cors` mode) hide content but leak timing. Response time/size differences via Resource Timing API enable XS-Search attacks (inferring search results, admin status).

**Defense**: `Cross-Origin-Resource-Policy: same-origin`, timing jitter, restrict `Timing-Allow-Origin`.

---

## CVE Summary (2024-2025)

| CVE | Product | CVSS | Type | Root Cause |
|-----|---------|------|------|------------|
| CVE-2024-25124 | Go Fiber | 9.4/7.5 | Wildcard + Credentials | Framework allowed `*` with credentials |
| CVE-2024-8183 | Prefect | 6.5 | Origin Reflection | No validation before reflecting origin |
| CVE-2025-5320 | Gradio | 6.3 | Origin Validation Error | Incorrect localhost/IPv6 validation |
| CVE-2025-57755 | Claude Code Router | 8.1 | Improper CORS Config | Permissive config exposes API keys |
| CVE-2024-1681 | Flask-CORS | 4.3 | Log Injection | CRLF injection via Origin header |
| CVE-2015-4520 | Firefox | 8.8 | Preflight Cache Poisoning | Cached preflight applied to credentialed requests |

---

## Attack-Spec-Defense Mapping

| Attack | Spec Reference | Defense |
|--------|---------------|---------|
| Origin Reflection | WHATWG Fetch §3.2.5 | Explicit whitelist, never reflect directly |
| Wildcard + Credentials | WHATWG Fetch §3.2.3 | Never `*` with credentials |
| Null Origin | WHATWG Fetch §3.2.5 | Never whitelist `null` |
| Regex Bypass | Implementation-specific | String matching or strict anchored regex |
| Subdomain XSS Chain | RFC 6454 §4 | Individual subdomain whitelist |
| Protocol Downgrade | RFC 6454 §8.4 | HTTPS origins only, HSTS |
| Preflight Cache Poisoning | WHATWG Fetch §4.10 | Low max-age, explicit OPTIONS handlers |
| Cache Poisoning (Vary) | HTTP Caching + CORS | Always `Vary: Origin` |
| Private Network Attack | WICG PNA Spec | No CORS for public→private, auth required |
| SameSite Bypass | RFC 6265bis + Fetch | Strict origin validation + CSRF tokens |
| Timing Side Channel | WHATWG Fetch §4.9 | CORP headers, timing jitter |

---

## Sources

**Specs**: [WHATWG Fetch](https://fetch.spec.whatwg.org/) | [RFC 6454](https://datatracker.ietf.org/doc/html/rfc6454) | [WICG PNA](https://wicg.github.io/private-network-access/)

**Research**: [PortSwigger CORS Exploitation](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties) | [PortSwigger CORS Academy](https://portswigger.net/web-security/cors) | [Intigriti CORS Guide](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities) | [HackTricks CORS](https://book.hacktricks.xyz/pentesting-web/cors-bypass) | [PT SWARM SameSite Bypass](https://swarm.ptsecurity.com/bypassing-browser-tracking-protection-for-cors-misconfiguration-abuse/) | [OWASP CORS Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
