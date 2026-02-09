# HTTP Protocol Security Analysis: Direct Extraction from RFC Specifications

> **Analysis Target**: RFC 9110 (HTTP Semantics), RFC 9112 (HTTP/1.1), RFC 9113 (HTTP/2), RFC 9114 (HTTP/3)
> **Methodology**: Direct extraction from spec text, cross-mapped with real-world CVEs and attack techniques
> **Research**: 2024-2025 vulnerabilities, BlackHat/DEF CON findings, PortSwigger Top 10

---

## Executive Summary

This analysis covers **27 security vulnerabilities** across HTTP protocol versions, organized into attack technique deep dives, version-specific issues, and latest CVEs. HTTP's fundamental design choices — statelessness, message framing flexibility, intermediary transparency, lenient parsing — create structural security challenges that cannot be fully mitigated without breaking compatibility. Advanced attacks like client-side desync, HTTP/2 downgrade exploitation, and response queue poisoning demonstrate how protocol translation introduces vulnerability classes not addressed by original specifications.

---

## Part I: Protocol Architecture and Security Design

### 1. Stateless Design (RFC 9110 §3.3)

*"A server MUST NOT assume that two requests on the same connection are from the same user agent unless the connection is secured and specific to that agent."*

HTTP provides no session tracking mechanism. All auth/session logic is application-layer, creating opportunities for session fixation, connection reuse attacks, and token replay. RFC 9110 §11.6.1 mandates credentials over confidential transport (HTTPS), but session management remains vulnerable to logical flaws.

### 2. Intermediary Transparency (RFC 9110 §3.7)

The spec classifies interception proxies as *"indistinguishable from on-path attackers"*. Non-encrypted traffic can be read/modified by any intermediary. Defense: HTTPS mandatory for any security-sensitive application.

### 3. Message Framing Ambiguity (RFC 9112 §6)

Multiple framing methods (Content-Length, Transfer-Encoding: chunked, connection close) combined with implementation-specific handling of conflicts create "interpretation differentials" — the root cause of request smuggling. RFC 9112 §6.3: *"If a message is received with both... the Transfer-Encoding overrides the Content-Length"* but uses "ought to" (not MUST) for error handling.

**CVEs**: CVE-2025-32094 (Akamai obs-fold smuggling), CVE-2023-25690 (Apache mod_proxy encoding).

### 4. Lenient Parsing (RFC 9112 §2.2)

*"A recipient SHOULD parse defensively with marginal expectations of conformance."* This robustness principle directly conflicts with security. Lenient parsing enables differential interpretation attacks, whitespace exploitation, and header deduplication issues.

---

## Part II: Header Processing Vulnerabilities

### 5. Host Header Trust (RFC 9110 §7.2)

Spec requires Host header but provides no validation guidance. Applications trusting Host enables password reset poisoning, cache poisoning, SSRF, and virtual host confusion. Defense: whitelist permitted domains at application layer.

### 6. CRLF Header Injection (RFC 9112 §5)

*"Field values containing CR, LF, or NUL characters are invalid and dangerous."* Unsanitized user input in header contexts enables response splitting, header injection, XSS, and cache poisoning. Defense: reject any input containing CR/LF; use APIs that auto-encode header values.

### 7. TE/CL Conflicts (RFC 9112 §6.3)

*"A sender MUST NOT send a Content-Length header field in any message that contains a Transfer-Encoding."* Violations handled differently by implementations → CL.TE, TE.CL, TE.TE smuggling attacks. Spec guidance assumes proxies correctly handle conflicts, but obfuscation defeats this.

### 8. Obsolete Line Folding (RFC 9112 §5.2)

Deprecated in RFC 7230 but still supported inconsistently. *"MUST either reject... or replace each obs-fold with SP"* — two valid behaviors create differential when intermediaries choose differently. CVE-2025-32094 exploited this.

### 9. Unvalidated Header Reflection (RFC 9110 §10)

No sanitization requirement for reflected User-Agent, Referer, X-Forwarded-For. Enables reflected XSS, log injection, SQL injection via headers. Defense: context-appropriate output encoding, CSP.

### 10. Authorization Header Exposure (RFC 9110 §11.6.2)

Credentials leaked via logs, caches, Referer headers, browser history. Defense: HTTPS mandatory, never include credentials in URLs, `Cache-Control: no-store` for authenticated responses.

---

## Part III: HTTP Version-Specific Vulnerabilities

### 11. HTTP/2 Stream Multiplexing DoS (RFC 9113 §5)

Stream multiplexing enables new DoS vectors: rapid stream reset (CVE-2023-44487 "Rapid Reset"), CONTINUATION frame flooding, priority tree manipulation, flow control exploitation. SETTINGS_MAX_CONCURRENT_STREAMS is SHOULD, not MUST.

### 12. HPACK Compression Attacks (RFC 9113 §10.3)

Stateful compression creates decompression bomb, CRIME-style side-channel, and table poisoning vectors. Defense: enforce SETTINGS_MAX_HEADER_LIST_SIZE, limit dynamic table, detect anomalous compression ratios.

### 13. HTTP/3 0-RTT Replay (RFC 9114 §10.9)

*"When 0-RTT is used, clients MUST only use it to carry idempotent requests."* 0-RTT data lacks replay protection. Non-idempotent requests (POST/DELETE) can be replayed for duplicate actions. Defense: only idempotent methods in 0-RTT, application-layer anti-replay tokens.

### 14. HTTP/3 Connection Contamination (RFC 9114 §3.3)

Connection reuse across origins without proper isolation enables cross-origin cookie theft and authority confusion. Defense: strict connection-to-origin binding, per-origin certificate validation.

---

## Part IV: Attack Technique Deep Dives

### 15. Request Smuggling

Exploits inconsistent message boundary parsing. Three variants:

**CL.TE**: Front-end uses Content-Length, back-end uses Transfer-Encoding:
```http
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**TE.CL**: Reverse — front-end chunked, back-end Content-Length.

**TE.TE**: Both support TE but one ignores obfuscated variant (`Transfer-Encoding: x`).

Impact: auth bypass, cache poisoning, credential hijacking. RFC gap: "ought to" (not MUST) for error handling.

### 16. Web Cache Poisoning

Unkeyed inputs (X-Forwarded-Host, Accept-Language) don't affect cache lookup but DO affect response generation. Attacker sends `X-Forwarded-Host: attacker.com` → response contains `<script src="https://attacker.com/malicious.js">` → cached for all users.

RFC 9111 §4: primary cache key is method + URI, but doesn't mandate including security-relevant headers.

### 17. Host Header Attacks

Password reset poisoning (`Host: attacker.com` → victim receives reset link to attacker domain), virtual host confusion (`Host: localhost` bypasses external restrictions), web cache poisoning via X-Forwarded-Host.

### 18. Client-Side Desync (CSD)

Servers responding before reading full Content-Length cause browser connection desynchronization. Victim's next request gets prepended with attacker's smuggled payload. Detection: send POST with Content-Length longer than body — immediate response = CSD vector.

Source: PortSwigger "Browser-Powered Desync Attacks" (Black Hat USA 2022).

### 19. Pause-Based Desync

Strategic timing of chunk size/data in separate TCP packets causes parsing desynchronization (Apache, Varnish). RFC 9112 §7.1 provides no timing requirements for chunk data arrival. Source: "Smashing the State Machine" (PortSwigger 2023).

### 20. HTTP/2 Downgrade Attacks (H2.TE, H2.CL)

Front-end speaks HTTP/2, rewrites to HTTP/1.1 for back-end. Translation introduces CL/TE ambiguity:

**H2.TE**: HTTP/2 frame length for front-end, Transfer-Encoding for back-end → smuggling.
**H2.CL**: Frame length vs Content-Length mismatch → back-end reads partial body.

Neither RFC 9113 nor 9112 address downgrade security. Source: James Kettle "HTTP/2: The Sequel is Always Worse" (DEF CON 29).

### 21. H2C Smuggling

`Upgrade: h2c` forwarded to back-end → attacker tunnels raw HTTP/2 frames through edge security that only validates HTTP/1.1. Bypasses WAF, header normalization, rate limiting. Defense: strip Upgrade headers at edge, disable h2c on back-end.

### 22. HTTP Request Tunneling

Complete HTTP/1.1 request in HTTP/2 body. Back-end processes body as second request, returning two responses. Front-end mismatches responses. Bypasses path restrictions, authentication.

### 23. Response Queue Poisoning

Smuggled request creates persistent response misalignment — **all** subsequent users on the same connection receive wrong responses. Attacker captures session tokens, CSRF tokens, PII across multiple victims. Devastating because it's persistent (not one-shot).

### 24. HTTP Parameter Pollution (HPP)

No spec guidance on duplicate parameter handling:
- PHP/Apache: last occurrence
- ASP.NET/IIS: concatenated with comma
- JSP/Tomcat: first occurrence
- Node.js/Express: array

Enables WAF bypass, auth bypass, CSRF token pollution. Real cases: PayPal payment manipulation, Twitter OAuth bypass.

### 25. Web Cache Deception

Path normalization differences between cache and origin. Cache sees `/account/settings.css` as static (caches), origin processes as `/account/settings` (returns sensitive data). Variants: encoded delimiters (`%2F`), path traversal (`..%2F`).

Source: PortSwigger "Gotta cache 'em all" (2024).

### 26. Transfer-Encoding Obfuscation

8+ categories of TE header obfuscation: whitespace variations, case variations, value obfuscation (`chunked;oops`), duplicate headers, line folding, non-standard delimiters, vertical tab/form feed, null bytes. Each tricks different implementations into ignoring or processing TE differently.

### 27. HTTP Pipelining Exploits

Pipelining (multiple requests without waiting for responses) enables DoS amplification, smuggling confusion, cache poisoning, timing attacks. Meris botnet uses pipelining for DDoS amplification. Modern browsers disabled pipelining by default.

---

## Part V: Latest CVEs (2024-2025)

| CVE | Year | Target | Attack | RFC Gap |
|-----|------|--------|--------|---------|
| CVE-2025-32094 | 2025 | Akamai | Obs-fold + OPTIONS smuggling | §5.2 allows two handling options |
| CVE-2025-66373 | 2025 | Various | Invalid chunk size smuggling | §7.1 no max size mandate |
| CVE-2025-8671 (MadeYouReset) | 2025 | HTTP/2 | Rapid RST_STREAM DoS | §5.4 no rate limit mandate |
| CVE-2024-24549 | 2024 | Tomcat | HTTP/2 excessive headers DoS | §6.5.2 no stream reset timing |
| CVE-2023-44487 (Rapid Reset) | 2023 | All HTTP/2 | Stream reset flood DoS | §5.4 no RST rate limit |
| CVE-2023-25690 | 2023 | Apache | mod_proxy encoding bypass | §4.2.1 no proxy normalization mandate |

**Browser-Powered Smuggling Evolution**: 2019 (server-side) → 2022 (client-side/browser) → 2023 (pause-based) → 2024 (continued refinement). Each variant exploits the same root causes: lenient parsing, multiple framing methods, no strict validation requirements.

---

## Part VI: Attack-Spec-Defense Mapping

| Attack | RFC Gap | Defense |
|--------|---------|---------|
| CL.TE/TE.CL Smuggling | §6.3 "ought to" not MUST | Reject requests with both headers |
| TE.TE Obfuscation | §2.2 lenient parsing | Only accept exact `Transfer-Encoding: chunked` |
| Response Splitting | §5 SHOULD not MUST reject | Reject CR/LF in header values |
| Host Header Poisoning | §3.2 no validation mandate | Whitelist expected Host values |
| Cache Poisoning | §4 unsafe cache key exclusions | Include security headers in cache key |
| HTTP/2 Rapid Reset | §5.4 no rate limit | RST_STREAM rate limiting |
| 0-RTT Replay | §10.9 app must handle replay | Idempotent methods only in 0-RTT |
| Client-Side Desync | §6.3 no full-body-read mandate | Read full Content-Length before responding |
| HTTP/2 Downgrade | No downgrade security guidance | End-to-end HTTP/2, strip CL/TE |
| H2C Smuggling | §3.4 no proxy security model | Strip Upgrade headers, disable h2c |
| Response Queue Poisoning | No queue recovery mechanism | Prevent smuggling, limit requests/connection |
| HPP | No duplicate parameter guidance | Canonicalize parameters, reject duplicates |
| Cache Deception | No normalization standard | Consistent normalization, `Cache-Control: no-store` |
| Pipelining DoS | §9.3.2 optional, no rate limit | Disable pipelining, rate limit |

---

## Conclusion

HTTP's security challenges stem from fundamental architectural decisions for flexibility, interoperability, and backward compatibility:

1. **Statelessness** delegates all security context to application layer
2. **Parsing flexibility** ("robustness principle") enables differential interpretation — 20+ TE obfuscation techniques exploit this
3. **Trust boundaries** — no protection against hostile intermediaries without HTTPS
4. **Version evolution** — each version introduces new surfaces (HTTP/1.1: smuggling; HTTP/2: multiplexing DoS, downgrade; HTTP/3: 0-RTT replay, contamination)
5. **Spec gaps** — SHOULD instead of MUST, multiple handling options, no normalization mandates

Many vulnerabilities cannot be fixed at protocol level without breaking compatibility. Defense requires defense-in-depth: strict parsing, comprehensive validation, encrypted transport, application-layer controls, and staying current with evolving techniques.

---

## Sources

**RFCs**: [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html), [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html), [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html), [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html), [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html)

**Research**: [PortSwigger Request Smuggling](https://portswigger.net/web-security/request-smuggling) | [Browser-Powered Desync](https://portswigger.net/research/browser-powered-desync-attacks) | [HTTP/2 Downgrading](https://portswigger.net/web-security/request-smuggling/advanced/http2-downgrading) | [Cache Deception](https://portswigger.net/web-security/web-cache-deception) | [Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine) | [Top 10 2024](https://portswigger.net/research/top-10-web-hacking-techniques-of-2024)

**CVEs**: [Akamai CVE-2025-32094](https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling) | [MadeYouReset](https://www.akamai.com/blog/security/response-madeyoureset-http2-protocol-attacks) | [OWASP Host Header](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing-for-Host-Header-Injection) | [HPP](https://www.imperva.com/learn/application-security/http-parameter-pollution/)
