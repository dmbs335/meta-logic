# WebSocket Protocol Security Analysis: Direct Extraction from RFC Specifications

> **Analysis Target**: RFC 6455 (The WebSocket Protocol), RFC 7692 (WebSocket Compression Extensions)
> **Methodology**: Direct extraction from specification text, cross-referenced with latest CVE data and security research
> **Latest Cases**: CVE-2024-55591, CVE-2025-52882, CVE-2024-26135, CSWSH attacks (2024-2025)
> **Analysis Date**: February 2026

## Executive Summary

The WebSocket protocol (RFC 6455) provides full-duplex communication but relies heavily on correct implementation of spec-mandated requirements. Key security issues:

1. **Origin validation** - SHOULD (not MUST) → CSWSH attacks
2. **Frame masking** - Infrastructure protection requirement
3. **Compression side-channels** - CRIME/BREACH attacks
4. **No standard authentication** - Implementation vulnerabilities
5. **DoS via resource exhaustion** - Stateful connection management

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

**Defense**:
```python
ALLOWED_ORIGINS = ['https://app.example.com']
if request.headers.get('Origin') not in ALLOWED_ORIGINS:
    return 403
```

### 2. Frame Masking (RFC 6455 §10.3)

**Spec**: *"A client MUST mask all frames"*

**Purpose**: Prevent cache poisoning and proxy command injection

**Defense**:
```python
if frame.from_client and not frame.is_masked:
    send_close_frame(1002)  # Protocol error
```

### 3. Handshake Authentication (RFC 6455 §4.2.2)

**Spec**: SHA-1 hash of `Sec-WebSocket-Key` + GUID `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`

**Defense**:
```python
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
accept_key = base64.b64encode(
    hashlib.sha1((client_key + WEBSOCKET_GUID).encode()).digest()
)
```

---

## Part II: Data Framing Vulnerabilities

### 4. UTF-8 Validation (RFC 6455 §8.1)

**Spec**: *"MUST fail the WebSocket connection"* on invalid UTF-8

**Attack**: Overlong UTF-8 encoding to bypass filters

**Defense**:
```python
frame.payload.decode('utf-8', errors='strict')  # Raises on invalid UTF-8
```

### 5. Fragmentation DoS (RFC 6455 §5.4)

**Issue**: No spec limits on fragments

**Attack**: Slowloris-style incomplete fragmented messages

**Defense**:
```python
MAX_FRAGMENTS = 1000
MAX_MESSAGE_SIZE = 1 * 1024 * 1024
FRAGMENT_TIMEOUT = 30  # seconds
```

### 6. Payload Length Overflow (RFC 6455 §5.2)

**Issue**: Allows up to 2^63-1 bytes

**CVEs**:
- CVE-2020-36406: uWebSockets buffer overflow
- CVE-2020-27813: Gorilla WebSocket integer overflow

**Defense**:
```python
MAX_PAYLOAD = 10 * 1024 * 1024
if length > MAX_PAYLOAD:
    send_close_frame(1009)  # Message too big
```

---

## Part III: Extensions & Subprotocols

### 7. Compression (RFC 7692)

**Spec Warning**: *"Known exploit when history-based compression is combined with secure transport"*

**Attack**: CRIME/BREACH side-channel

**CVEs**:
- TINKERPOP-2700: WebSocket compression → CRIME/BREACH
- ASP.NET Core #53640: Blazor security warning

**Defense**:
```python
# Never compress sensitive data
if sensitive:
    frame = Frame(rsv1=0, payload=data)  # No compression
```

### 8. Subprotocol Authentication (RFC 6455 §1.9)

**Anti-pattern**: Tokens in `Sec-WebSocket-Protocol` header (logged!)

**Defense**: Post-handshake authentication
```python
auth_msg = await ws.recv(timeout=5)
if not validate_token(auth_msg['token']):
    await ws.close(1008)
```

---

## Part IV: Latest CVE Analysis (2024-2025)

### CVE-2024-55591/CVE-2025-24472: FortiOS Auth Bypass
- **CVSS**: 9.6 Critical
- **Status**: Exploited in the wild
- **Issue**: Authentication bypass via WebSocket handshake

### CVE-2025-52882: Claude Code CSWSH
- **CVSS**: 8.8 High
- **Attack**: Malicious website → localhost WebSocket → file read + code execution
- **Fix**: Origin validation for localhost connections

### CVE-2024-26135: MeshCentral CSWSH
- **Issue**: No Origin validation + cookie auth + no CSRF token
- **Fix**: Validate Origin against allowlist

---

## Attack-Spec-Defense Mapping

| Attack | Spec Behavior | RFC | Defense |
|--------|--------------|-----|---------|
| CSWSH | Origin is SHOULD | §10.2 | Validate Origin allowlist |
| Cache Poisoning | Unmasked frames | §10.3 | Enforce masking (MUST) |
| CRIME/BREACH | Compression | RFC 7692 §8 | No compression for secrets |
| Memory Exhaustion | No fragment limits | §5.4 | MAX_FRAGMENTS + timeout |
| Integer Overflow | 2^63-1 bytes allowed | §5.2 | Validate before allocation |
| UTF-8 Bypass | Invalid UTF-8 → fail | §8.1 | Strict validation |
| Auth Bypass | No standard auth | §10.5 | Post-handshake auth |

---

## Security Checklist

### Handshake
- [ ] Validate Origin against allowlist
- [ ] Verify Sec-WebSocket-Version: 13
- [ ] Check Sec-WebSocket-Key (16 bytes)
- [ ] Handshake timeout (10s)

### Frames
- [ ] Reject unmasked client frames
- [ ] Validate UTF-8 in text frames
- [ ] Limit payload length
- [ ] Limit fragments (count, size, time)

### Authentication
- [ ] Post-handshake auth message
- [ ] Never skip Origin check
- [ ] CSRF token required
- [ ] No tokens in headers

### DoS Protection
- [ ] Max connections per IP
- [ ] Message rate limiting
- [ ] Idle timeout
- [ ] Ping/pong heartbeat

### Extensions
- [ ] Disable compression for sensitive data
- [ ] Extension allowlist only

---

## Sources

- [RFC 6455: WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)
- [RFC 7692: WebSocket Compression](https://datatracker.ietf.org/doc/html/rfc7692)
- [CVE-2024-55591 FortiOS](https://insights.integrity360.com/cve-2024-55591-being-exploited-in-the-wild-critical-authentication-bypass-in-node.js-websocket-module)
- [CVE-2025-52882 Claude Code](https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/)
- [CVE-2024-26135 MeshCentral](https://github.com/Ylianst/MeshCentral/security/advisories/GHSA-cp68-qrhr-g9h8)
- [BlackHat 2012: Hacking WebSockets](https://media.blackhat.com/bh-us-12/Briefings/Shekyan/BH_US_12_Shekyan_Toukharian_Hacking_Websocket_Slides.pdf)
- [OWASP WebSocket Security](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- [PortSwigger: Testing WebSockets](https://portswigger.net/web-security/websockets)
- [Pentest-Tools: CSWSH](https://pentest-tools.com/blog/cross-site-websocket-hijacking-cswsh)
- [Ably: WebSocket Security](https://ably.com/topic/websocket-security)
- [Apache TINKERPOP-2700](https://issues.apache.org/jira/browse/TINKERPOP-2700)
- [Cloudflare: Slowloris Attack](https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/)

---

**End of Analysis**
