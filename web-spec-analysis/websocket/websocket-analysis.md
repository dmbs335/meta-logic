# WebSocket Protocol Security Analysis

> **Analysis Target**: RFC 6455 (The WebSocket Protocol), RFC 7692 (WebSocket Compression Extensions)
> **Methodology**: Direct extraction from specification text, cross-referenced with CVE data and security research
> **Latest Cases**: CVE-2024-55591, CVE-2025-52882, CVE-2024-26135, CSWSH attacks (2024-2025)

## Executive Summary

The WebSocket protocol (RFC 6455) provides full-duplex communication but relies heavily on correct implementation of spec-mandated requirements. Key security issues:

1. **Origin validation** — SHOULD (not MUST) → CSWSH attacks
2. **Frame masking** — Infrastructure protection requirement
3. **Compression side-channels** — CRIME/BREACH attacks
4. **No standard authentication** — Implementation vulnerabilities
5. **DoS via resource exhaustion** — Stateful connection management

---

## Part I: Protocol Architecture

### 1. Origin-Based Security Model (RFC 6455 §10.2)

**Spec**: *"Servers...SHOULD verify the |Origin| field"* (SHOULD, not MUST)

**Security Implication**: Optional origin validation → Cross-Site WebSocket Hijacking (CSWSH)

**Attack Vector**:
```html
<script>
var ws = new WebSocket("wss://victim.com/chat");
ws.onopen = function() {
    ws.send(JSON.stringify({action: "transfer_funds", amount: 10000}));
};
</script>
```

**Real-World CVEs**:
- CVE-2024-26135 (MeshCentral): CSWSH via missing Origin validation
- CVE-2025-52882 (Claude Code CVSS 8.8): Localhost WebSocket bypass

**Defense**: Validate Origin against allowlist.

### 2. Frame Masking (RFC 6455 §10.3)

**Spec**: *"A client MUST mask all frames"*

**Purpose**: Prevent cache poisoning and proxy command injection. Reject unmasked client frames with close code 1002 (Protocol error).

### 3. Handshake Authentication (RFC 6455 §4.2.2)

**Spec**: SHA-1 hash of `Sec-WebSocket-Key` + GUID `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`

This validates proper WebSocket handshake but provides no authentication — authentication must be implemented separately.

---

## Part II: Data Framing Vulnerabilities

### 4. UTF-8 Validation (RFC 6455 §8.1)

**Spec**: *"MUST fail the WebSocket connection"* on invalid UTF-8

**Attack**: Overlong UTF-8 encoding to bypass filters (e.g., `\xC0\xBC` for `<` to bypass XSS filters).

**Defense**: Strict UTF-8 validation — reject invalid sequences.

### 5. Fragmentation DoS (RFC 6455 §5.4)

**Issue**: No spec limits on fragments → Slowloris-style incomplete fragmented messages.

**Defense**: Enforce MAX_FRAGMENTS (1000), MAX_MESSAGE_SIZE (1MB), FRAGMENT_TIMEOUT (30s).

### 6. Payload Length Overflow (RFC 6455 §5.2)

**Issue**: Allows up to 2^63-1 bytes.

**CVEs**:
- CVE-2020-36406: uWebSockets buffer overflow
- CVE-2020-27813: Gorilla WebSocket integer overflow

**Defense**: Validate payload length before allocation, enforce MAX_PAYLOAD (10MB), close with 1009 (Message too big).

---

## Part III: Extensions & Subprotocols

### 7. Compression (RFC 7692)

**Spec Warning**: *"Known exploit when history-based compression is combined with secure transport"*

**Attack**: CRIME/BREACH side-channel — compressed encrypted data leaks plaintext length.

**CVEs**:
- TINKERPOP-2700: WebSocket compression → CRIME/BREACH
- ASP.NET Core #53640: Blazor security warning

**Defense**: Never compress sensitive data. Disable `permessage-deflate` for authenticated endpoints.

### 8. Subprotocol Authentication (RFC 6455 §1.9)

**Anti-pattern**: Tokens in `Sec-WebSocket-Protocol` header — gets logged by proxies and infrastructure.

**Defense**: Post-handshake authentication — require auth message within 5s timeout after connection, close with 1008 on failure.

### 9. GraphQL over WebSocket Security

GraphQL subscriptions commonly use WebSocket transport, introducing unique attack surface.

**Key CVEs**:
- **CVE-2023-38503** (Directus, CVSS 6.5): GraphQL subscriptions bypassed permission system → subscribe to unauthorized data streams
- **CVE-2025-27407** (graphql-ruby, CVSS 9.9): Unsafe deserialization in subscription resolver → RCE

**Cross-Site GraphQL Subscription Hijacking (2025)**: Attacker's page connects to victim's GraphQL WebSocket endpoint with victim's cookies → subscribes to private data or executes mutations.

**Defense**:
1. Validate Origin header
2. Token-based auth in `connection_init` (not cookies)
3. Enforce permissions per subscription
4. Disable mutations over WebSocket (prefer HTTP POST)

---

## Part IV: Latest CVE Analysis (2024-2025)

### CVE-2024-55591/CVE-2025-24472: FortiOS Auth Bypass
- **CVSS**: 9.6 Critical | **Status**: Exploited in the wild
- **Issue**: Authentication bypass via WebSocket handshake
- **Affected**: FortiOS 7.0.0 - 7.0.16, 7.2.0 - 7.2.10, 7.4.0 - 7.4.5
- **Impact**: Complete device takeover

### CVE-2025-52882: Claude Code CSWSH
- **CVSS**: 8.8 High
- **Attack**: Malicious website → localhost WebSocket → file read + code execution
- **Fix**: Origin validation for localhost connections

### CVE-2024-26135: MeshCentral CSWSH
- **Issue**: No Origin validation + cookie auth + no CSRF token
- **Fix**: Validate Origin against allowlist

### CVE-2024-21733: Apache Tomcat WebSocket Smuggling
- **CVSS**: 7.5 High
- **Affected**: Tomcat 8.5.7 - 8.5.63, 9.0.0-M11 - 9.0.43
- **Issue**: Incorrect HTTP/1.1 upgrade handling → HTTP request smuggling via WebSocket upgrade
- **Attack**: Proxy sees "Upgrade: websocket" → forwards to backend → backend rejects upgrade but processes smuggled second request in body
- **Fix**: Tomcat 8.5.64+, 9.0.44+

### CVE-2024-38355: Socket.IO Denial of Service
- **CVSS**: 7.3 High
- **Affected**: Socket.IO <2.5.0, >=3.0.0 <4.6.2
- **Issue**: Unhandled exception in WebSocket transport causes server crash
- **Fix**: Socket.IO 4.6.2+

### CVE-2024-21386: SignalR .NET Denial of Service
- **CVSS**: 7.5 High | **Affected**: .NET 6.0, 7.0, 8.0
- **Issue**: WebSocket frame processing DoS via crafted frames
- **Fix**: .NET security updates (January 2024)

### CVE-2025-10148: curl WebSocket Predictable Mask
- **CVSS**: 5.3 Medium | **Affected**: curl 7.86.0 - 8.15.0
- **Issue**: WebSocket mask pattern not updated per frame → fixed mask throughout connection
- **Attack**: Cache poisoning via predictable XOR masks when proxy confuses WebSocket for HTTP traffic
- **Requirements**: Clear text ws:// (not wss://), vulnerable proxy
- **Fix**: curl 8.16.0+ (updates mask per frame per RFC 6455)

### CVE-2024-41570: Havoc C2 SSRF via WebSocket
- **CVSS**: 9.8 Critical | **Affected**: Havoc C2 Framework 0.7
- **Issue**: Unauthenticated SSRF in demon callback handling → arbitrary network requests to cloud metadata, internal APIs
- **Fix**: Havoc 0.8+ (authentication required for demon callbacks)

### CVE-2024-37890: ws npm Package DoS
- **CVSS**: 7.5 High | **Affected**: ws <8.17.1
- **Issue**: No limit on HTTP header count during upgrade → memory exhaustion
- **Fix**: ws 8.17.1+ limits headers to 100

### CVE-2025-66902: websocket-server Input Validation
- **CVSS**: 6.5 Medium | **Affected**: websocket-server (Go) <1.3.0
- **Issue**: No UTF-8 validation on text frames (violates RFC 6455 §8.1) → overlong encoding bypasses content filters
- **Fix**: websocket-server 1.3.0+

### CVE-2024-28179: jupyter-server-proxy Auth Bypass
- **CVSS**: 8.1 High | **Affected**: jupyter-server-proxy <3.2.3, <4.1.1
- **Issue**: WebSocket proxying does not validate user authentication → unauthenticated RCE via proxied applications
- **Fix**: jupyter-server-proxy 3.2.3+ or 4.1.1+

### CVE-2025-41254: Spring Framework CSRF Bypass
- **CVSS**: 7.4 High | **Affected**: Spring Framework 5.3.0 - 5.3.32, 6.0.0 - 6.0.17, 6.1.0 - 6.1.4
- **Issue**: CSRF protection not enforced on WebSocket STOMP endpoints → CSWSH
- **Fix**: Spring Framework 5.3.33+, 6.0.18+, 6.1.5+

### CVE-2020-8823: SockJS Reflected XSS
- **CVSS**: 6.1 Medium | **Affected**: SockJS <0.3.20
- **Issue**: Reflected XSS in WebSocket fallback endpoint
- **Note**: SockJS deprecated — migrate to native WebSocket or Socket.IO

---

## Part V: WebSocket Libraries Security

### Library CVE Summary

| Library | Key CVEs | Critical Issue |
|---------|----------|----------------|
| **Socket.IO** (Node.js) | CVE-2024-38355, CVE-2022-2421 | DoS, CORS bypass |
| **SignalR** (.NET) | CVE-2024-21386, CVE-2025-41254 | DoS, CSRF bypass |
| **ws** (npm) | CVE-2024-37890, CVE-2021-32640 | Header flood DoS, ReDoS |
| **gorilla/websocket** (Go) | CVE-2020-27813 | Integer overflow |
| **SockJS** | CVE-2020-8823 | XSS (deprecated, migrate away) |

### Common Secure Configuration Principles

All libraries require the same core security measures:
1. **Origin validation**: Configure `CheckOrigin`/`cors`/`verifyClient` with explicit allowlist
2. **Payload limits**: Set `maxPayload`/`MaximumReceiveMessageSize`/`ReadLimit` (recommended: 1MB)
3. **Compression**: Disable `permessage-deflate` for sensitive data
4. **Heartbeat**: Configure ping/pong (25-30s interval) with pong timeout
5. **Authentication**: Post-handshake token validation, not cookies
6. **Rate limiting**: Per-connection message rate limits

---

## Part VI: Advanced Attack Techniques

### 6.1: WebSocket Smuggling

**Attack Context**: HTTP/1.1 proxies and backend servers may disagree on WebSocket upgrade handling.

```
Client → Proxy (allows upgrade) → Backend (rejects upgrade, processes body as HTTP)
```

**Attack**: Send Upgrade request with Content-Length containing a smuggled HTTP request in the body. Proxy forwards thinking it's a WebSocket upgrade. Backend rejects upgrade but processes the Content-Length, interpreting the smuggled request separately.

**Impact**: Bypass authentication, access internal endpoints, cache poisoning.

**Defense**:
1. Reject Upgrade requests with Content-Length
2. Only allow upgrades on designated WebSocket endpoints
3. Upgrade to patched server versions

### 6.2: Cache Poisoning via Predictable Masks

**Background**: RFC 6455 requires client frames to be XOR-masked with 32-bit random key per frame. Weak or fixed masks enable cache poisoning.

**CVE-2025-10148 (curl)**: Mask pattern persisted throughout connection instead of updating per frame. With predictable masks and a misconfigured proxy that interprets WebSocket traffic as HTTP, attacker can craft payloads that the proxy caches as legitimate responses.

**Defense**: Use CSPRNG for masking, update mask per frame (RFC 6455 requirement).

---

## Attack-Spec-Defense Mapping

| Attack | Spec Behavior | RFC | Defense |
|--------|--------------|-----|---------|
| CSWSH | Origin is SHOULD | §10.2 | Validate Origin allowlist |
| GraphQL CSWSH | Origin is SHOULD | §10.2 | Origin + token-based auth |
| Cache Poisoning | Unmasked frames | §10.3 | Enforce masking (MUST) |
| Predictable Mask | Weak client RNG | §10.3 | CSPRNG for masking |
| WebSocket Smuggling | Upgrade ambiguity | §4.1 | Strict upgrade validation |
| CRIME/BREACH | Compression | RFC 7692 §8 | No compression for secrets |
| Memory Exhaustion | No fragment limits | §5.4 | MAX_FRAGMENTS + timeout |
| Integer Overflow | 2^63-1 bytes allowed | §5.2 | Validate before allocation |
| UTF-8 Bypass | Invalid UTF-8 → fail | §8.1 | Strict validation |
| Auth Bypass | No standard auth | §10.5 | Post-handshake auth |
| DoS (Header Flood) | No header limits | §4.1 | Limit header count |
| SSRF via Redirect | Client follows redirects | N/A | Block redirects |

---

## Security Checklist

### Handshake
- [ ] Validate Origin against allowlist
- [ ] Verify Sec-WebSocket-Version: 13
- [ ] Handshake timeout (10s)
- [ ] Limit HTTP headers count (≤100)
- [ ] Reject if Content-Length present with Upgrade

### Frames
- [ ] Reject unmasked client frames
- [ ] Validate UTF-8 in text frames (strict mode)
- [ ] Limit payload length (≤10MB)
- [ ] Limit fragments (count, size, time)

### Authentication
- [ ] Post-handshake auth message (timeout: 5s)
- [ ] Never skip Origin check
- [ ] CSRF token required (for cookie-based auth)
- [ ] No tokens in headers (use post-handshake)
- [ ] Token-based auth for GraphQL (not cookies)
- [ ] Validate permissions per subscription/message

### DoS Protection
- [ ] Max connections per IP
- [ ] Message rate limiting
- [ ] Idle timeout (60-300s)
- [ ] Ping/pong heartbeat (25-30s interval)

### Extensions
- [ ] Disable compression for sensitive data
- [ ] Extension allowlist only
- [ ] No deprecated protocols (SockJS, Engine.IO v3)

### GraphQL over WebSocket
- [ ] Origin validation
- [ ] connection_init authentication required
- [ ] Subscription permission checks
- [ ] Disable mutations over WebSocket

### Transport
- [ ] WSS only (reject ws://)
- [ ] TLS 1.2+ minimum (TLS 1.3 preferred)
- [ ] HSTS header enabled

---

## Sources

### RFCs & Standards
- [RFC 6455: WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)
- [RFC 7692: WebSocket Compression](https://datatracker.ietf.org/doc/html/rfc7692)
- [GraphQL over WebSocket Protocol](https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md)

### CVE Databases & Advisories
- [CVE-2024-55591 / CVE-2025-24472: FortiOS](https://insights.integrity360.com/cve-2024-55591-being-exploited-in-the-wild-critical-authentication-bypass-in-node.js-websocket-module)
- [CVE-2025-52882: Claude Code CSWSH](https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/)
- [CVE-2024-26135: MeshCentral CSWSH](https://github.com/Ylianst/MeshCentral/security/advisories/GHSA-cp68-qrhr-g9h8)
- [CVE-2024-21733: Apache Tomcat WebSocket Smuggling](https://lists.apache.org/thread/vkk0r38cc485w88cdrho45kbb60xs2p0)
- [CVE-2024-38355: Socket.IO DoS](https://github.com/socketio/socket.io/security/advisories/GHSA-3h3p-588w-2j72)
- [CVE-2024-21386: SignalR DoS](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21386)
- [CVE-2025-10148: curl Predictable Mask](https://curl.se/docs/CVE-2025-10148.html)
- [CVE-2024-41570: Havoc C2 SSRF](https://github.com/diemoeve/CVE-2024-41570)
- [CVE-2024-37890: ws npm Header Flood](https://github.com/websockets/ws/security/advisories/GHSA-3h5v-q724-j2mg)
- [CVE-2025-66902: websocket-server UTF-8](https://nvd.nist.gov/vuln/detail/CVE-2025-66902)
- [CVE-2024-28179: jupyter-server-proxy Auth Bypass](https://github.com/jupyterhub/jupyter-server-proxy/security/advisories/GHSA-w3vc-fx9p-wp4v)
- [CVE-2025-41254: Spring CSRF Bypass](https://spring.io/security/cve-2025-41254)
- [CVE-2020-8823: SockJS XSS](https://nvd.nist.gov/vuln/detail/CVE-2020-8823)
- [CVE-2023-38503: Directus Permission Bypass](https://github.com/directus/directus/security/advisories/GHSA-gggm-66rh-pp98)
- [CVE-2025-27407: graphql-ruby RCE](https://rubysec.com/advisories/CVE-2025-27407/)
- [CVE-2020-36406: uWebSockets Overflow](https://github.com/uNetworking/uWebSockets/issues/1234)
- [CVE-2020-27813: Gorilla Overflow](https://github.com/gorilla/websocket/security/advisories/GHSA-jf24-p9p9-4rjh)

### Security Research
- [BlackHat 2012: Hacking WebSockets](https://media.blackhat.com/bh-us-12/Briefings/Shekyan/BH_US_12_Shekyan_Toukharian_Hacking_Websocket_Slides.pdf)
- [BlackHat USA 2025: ECScape - Amazon ECS Cross-Task Credential Theft](https://www.scworld.com/news/amazon-ecs-privilege-escalation-risk-described-at-black-hat-usa-2025)
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- [PortSwigger: Testing WebSockets](https://portswigger.net/web-security/websockets)
- [Pentest-Tools: CSWSH Methodology](https://pentest-tools.com/blog/cross-site-websocket-hijacking-cswsh)
