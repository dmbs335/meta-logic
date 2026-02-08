# HTTP Protocol Security Analysis: Direct Extraction from RFC Specifications

> **Analysis Target**: RFC 9110 (HTTP Semantics), RFC 9112 (HTTP/1.1), RFC 9113 (HTTP/2), RFC 9114 (HTTP/3)
> **Methodology**: Direct extraction of security implications from specification text, cross-mapped with real-world CVEs and attack techniques
> **Latest Research Incorporated**: 2024-2025 vulnerabilities, BlackHat/DEF CON findings, CISA KEV catalog

---

## Executive Summary

This analysis examines the HTTP protocol family through the lens of their official IETF RFC specifications, extracting security-critical design decisions and mapping them to real-world exploitation vectors. Unlike conventional security guides, this document traces vulnerabilities back to specific RFC sections, revealing how specification ambiguities, parsing flexibility, and backward compatibility create systemic attack surfaces.

**Scope**: This comprehensive analysis covers **27 distinct security vulnerabilities** organized into seven parts:
- **Part I**: Protocol Architecture (4 items)
- **Part II**: Header Processing Vulnerabilities (6 items)
- **Part III**: HTTP Version-Specific Vulnerabilities (4 items)
- **Part IV**: Advanced Attack Technique Deep Dives (13 items)
- **Part V**: Latest CVEs and Real-World Cases (2024-2025)
- **Part VI**: Complete Attack-Spec-Defense Mapping (30 attack types)
- **Part VII**: Security Verification Checklist (80+ actionable items)

**Research Foundation**: Analysis incorporates PortSwigger's Top 10 Web Hacking Techniques (2023-2024), including cutting-edge research on browser-powered desync attacks, HTTP/2 downgrade exploitation, client-side desync, response queue poisoning, web cache deception, and HTTP parameter pollution.

**Key Finding**: HTTP's fundamental design choices—statelessness, message framing flexibility, intermediary transparency, and lenient parsing—while enabling scalability and interoperability, create structural security challenges that cannot be fully mitigated without breaking compatibility. Advanced attack techniques like client-side desync and HTTP/2 downgrade attacks demonstrate how protocol translation and version interoperability introduce new vulnerability classes not addressed by original specifications.

---

## Part I: Protocol Architecture and Security Design

### 1. Stateless Design and Session Security Implications (RFC 9110 §3.3)

**Specification Requirement**:
*"A server MUST NOT assume that two requests on the same connection are from the same user agent unless the connection is secured and specific to that agent."* (RFC 9110 §3.3)

**Security Implication**:
HTTP's stateless design means the protocol itself provides no mechanism for tracking client identity across requests. This fundamental architectural choice delegates all authentication and authorization logic to the application layer, creating opportunities for implementation errors.

**Attack Vectors**:
- **Session Fixation**: Since HTTP has no built-in session concept, applications implement their own session tracking (typically via cookies). Attackers can inject known session identifiers before authentication.
- **Connection Reuse Attacks**: In non-TLS contexts, connection reuse by different clients (e.g., through proxies) can lead to request attribution errors if applications incorrectly assume connection = identity.
- **Token Replay**: Stateless tokens (like JWTs) cannot be revoked at the protocol level—once issued, they remain valid until expiration.

**Real-World Examples**:
- Many OAuth implementations suffer from authorization code replay attacks because HTTP provides no replay protection mechanism.
- Session management vulnerabilities consistently appear in OWASP Top 10 due to the lack of protocol-level guidance.

**Spec-Based Defense**:
RFC 9110 §11.6.1 mandates: *"Credentials MUST be transmitted over a connection that provides confidentiality and integrity protections."* This requires HTTPS for any authentication scheme, but application-layer session management remains vulnerable to logical flaws.

---

### 2. Trust Boundaries and Intermediary Transparency (RFC 9110 §3.7)

**Specification Behavior**:
*"Intermediaries that are not under the control of the client or server can observe, modify, or filter messages."* (RFC 9110 §17.2)

The specification explicitly acknowledges that HTTP allows intermediaries (proxies, gateways, CDNs) to exist in the request path and classifies "interception proxies" as *"indistinguishable from on-path attackers"* at the protocol level (RFC 9110 §3.7.9).

**Security Implication**:
HTTP's architectural assumption is that all non-encrypted traffic is potentially hostile. The protocol provides no mechanism for endpoints to detect or prevent intermediary manipulation.

**Attack Vectors**:
- **Man-in-the-Middle (MITM)**: Unencrypted HTTP traffic can be read and modified by any intermediary.
- **SSL Stripping**: Attackers can downgrade HTTPS connections to HTTP at intermediary points, exploiting HTTP's lack of upgrade enforcement.
- **Request/Response Manipulation**: Proxies can modify headers, redirect requests, or inject content without detection in non-TLS contexts.

**Real-World Examples**:
- Public WiFi networks routinely inject advertising into HTTP responses.
- Corporate proxies intercept TLS connections using custom root certificates, breaking end-to-end security assumptions.
- ISPs have injected JavaScript tracking code into unencrypted HTTP responses for analytics.

**Spec-Based Defense**:
The specification's only defense is encryption: *"Clients, servers, and proxies MUST NOT include sensitive information in URI components unless the communication is secured."* (RFC 9110 §17.9) This effectively mandates HTTPS for any security-sensitive application.

---

### 3. Message Framing Ambiguity (RFC 9112 §6)

**Specification Flexibility**:
RFC 9112 allows multiple message framing mechanisms:
- Content-Length header (explicit size)
- Transfer-Encoding: chunked (dynamic framing)
- Connection close (implicit end)

The spec states: *"If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length. Such a message might indicate an attempt to perform request smuggling."* (RFC 9112 §6.3)

**Security Implication**:
The existence of multiple framing methods, combined with implementation-specific handling of conflicting headers, creates "interpretation differentials" between intermediaries and origin servers.

**Attack Vectors**:
- **HTTP Request Smuggling (CL.TE, TE.CL, TE.TE)**: When front-end and back-end servers disagree on message boundaries, attackers can inject requests that bypass security controls.
- **Response Queue Poisoning**: Misaligned message framing causes responses to be matched with wrong requests, potentially leaking sensitive data.
- **Cache Poisoning**: Smuggled requests can pollute caches with attacker-controlled content.

**Real-World Examples**:
- **CVE-2025-32094**: HTTP/1.x OPTIONS requests with obsolete line folding caused parsing discrepancies between Akamai servers, enabling request smuggling.
- **Apache mod_proxy (CVE-2023-25690)**: Incorrect encoding in mod_proxy allowed request URLs with wrong encoding to be sent to backends, bypassing authentication.
- PortSwigger's 2019 research on request smuggling identified thousands of vulnerable websites using popular web servers and CDNs.

**Spec-Based Defense**:
RFC 9112 §6.3 mandates: *"A server MUST NOT send a Content-Length header field in any response with a status code of 1xx (Informational) or 204 (No Content)."* However, it allows leniency: *"A server MAY reject the request with a 400 (Bad Request) status code"* when conflicts occur—the MAY (not MUST) creates implementation inconsistency.

---

### 4. Lenient Parsing Philosophy (RFC 9112 §2.2)

**Specification Requirement**:
*"A recipient SHOULD parse defensively with marginal expectations of conformance."* (RFC 9110 §2.3)

*"In the interest of robustness, a server that is expecting to receive and parse a request-line SHOULD ignore at least one empty line (CRLF) received prior to the request-line."* (RFC 9112 §2.2)

**Security Implication**:
HTTP's "robustness principle" (be liberal in what you accept) directly conflicts with security best practices. Lenient parsing allows attackers to craft ambiguous messages that different implementations interpret differently.

**Attack Vectors**:
- **Parsing Differential Attacks**: Crafting requests with subtle violations that some parsers correct while others reject, enabling bypass of security filters.
- **Whitespace Exploitation**: The spec allows whitespace tolerance in various contexts, which attackers exploit for obfuscation.
- **Header Deduplication Issues**: When duplicate headers appear, different implementations may use first, last, concatenate, or error—enabling injection attacks.

**Real-World Examples**:
- **Request Smuggling via Whitespace**: Different tolerance for whitespace between header name and colon has enabled smuggling attacks.
- **Normalization Bypass**: Security filters that normalize requests differently than origin servers can be bypassed.

**Spec-Based Defense**:
RFC 9112 §5.1 requires strictness in specific cases: *"A server MUST reject, with a response status code of 400 (Bad Request), any received request message that contains whitespace between a header field name and colon."* But this strictness is selective—many other parsing ambiguities remain.

---

## Part II: Header Processing Vulnerabilities

### 5. Host Header Trust Assumption (RFC 9110 §7.2)

**Specification Requirement**:
*"A client MUST send a Host header field in all HTTP/1.1 request messages."* (RFC 9112 §3.2)

The spec requires the Host header but provides no validation guidance for servers receiving it, implicitly treating it as authoritative for routing decisions.

**Security Implication**:
Applications often trust the Host header value without validation, assuming it reflects the legitimate server hostname. However, clients control this header completely.

**Attack Vectors**:
- **Password Reset Poisoning**: Attacker manipulates Host header in password reset request. Application generates reset link using attacker's domain. Victim receives email with malicious link containing valid reset token.
- **Web Cache Poisoning**: Injecting malicious Host header values that get reflected in responses and cached, affecting subsequent users.
- **Server-Side Request Forgery (SSRF)**: Applications using Host header to construct internal API calls can be tricked into making requests to attacker-controlled hosts.
- **Virtual Host Confusion**: Multi-tenant servers may route requests to wrong applications based on manipulated Host headers.

**Real-World Examples**:
- Password reset poisoning is documented in OWASP testing guides and has affected major platforms.
- Web cache poisoning via Host header has enabled XSS attacks through reflected payloads.

**Spec-Based Defense**:
RFC 9110 §4.2.1 requires: *"A sender MUST NOT generate an 'http' or 'https' URI with an empty host."* However, it provides no requirement for servers to validate Host header against expected values. The defense must be implemented at application layer by whitelisting permitted domains.

---

### 6. Header Injection via CRLF Sequences (RFC 9112 §5)

**Specification Requirement**:
*"A sender MUST NOT generate a bare CR (carriage return) anywhere within a protocol element."* (RFC 9112 §2.2)

*"Field values containing CR, LF, or NUL characters are invalid and dangerous, due to the varying ways that implementations might parse and interpret those characters."* (RFC 9110 §5.5)

**Security Implication**:
HTTP uses CRLF (\\r\\n) sequences as structural delimiters. If user input containing CRLF sequences reaches header contexts without sanitization, attackers can inject arbitrary headers or even entire responses.

**Attack Vectors**:
- **HTTP Response Splitting**: Injecting `\\r\\n\\r\\n` followed by malicious response body to serve arbitrary content.
- **Header Injection**: Adding extra headers like `Set-Cookie` to hijack sessions or `Location` to cause open redirects.
- **XSS via Header Reflection**: Injecting headers that get reflected in error pages or responses with attacker-controlled content.
- **Cache Poisoning**: Injected headers can manipulate cache directives to poison shared caches.

**Real-World Examples**:
- Classic PHP applications passing user input to `header()` function without sanitization.
- URL-based header injection in redirects where Location header includes unsanitized input.
- Cookie injection attacks via CRLF in cookie values.

**Spec-Based Defense**:
RFC 9112 §11.1 warns: *"Implementations that fail to prevent the injection of such characters into HTTP messages may be vulnerable to security exploits."*

The specification mandates rejection but allows flexibility: *"A server that receives a field line that contains a bare CR in a message that is not acting as an HTTP/1.1 tunnel SHOULD reject the message with a 400 (Bad Request) status code."*

Proper defense requires:
1. Input validation rejecting any input containing CR or LF characters
2. Using APIs that automatically encode/escape header values
3. Never directly concatenating user input into raw header strings

---

### 7. Transfer-Encoding and Content-Length Conflicts (RFC 9112 §6)

**Specification Requirement**:
*"A sender MUST NOT send a Content-Length header field in any message that contains a Transfer-Encoding header field."* (RFC 9112 §6.3)

*"If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length."* (RFC 9112 §6.3)

**Security Implication**:
The specification defines clear precedence rules but acknowledges that implementations may handle violations differently. This creates a critical attack surface when intermediaries and origin servers disagree.

**Attack Vectors**:
- **CL.TE Request Smuggling**: Front-end uses Content-Length, back-end uses Transfer-Encoding. Attacker sends ambiguous message that front-end sees as one request but back-end sees as two.
- **TE.CL Request Smuggling**: Reverse of CL.TE—front-end uses Transfer-Encoding, back-end uses Content-Length.
- **TE.TE Obfuscation**: Both support Transfer-Encoding but attacker obfuscates the header so one server ignores it.

**Real-World Examples**:
- **Apache mod_http2 logging** (CVE-2020-11993): HTTP/2 module logging on wrong connection caused memory corruption (not smuggling).
- **Apache Tomcat HTTP/2** (CVE-2024-24549): HTTP/2 stream not reset until after all headers processed, allowing DoS via excessive headers.
- Thousands of vulnerable configurations identified by PortSwigger's 2019 research.

**Spec-Based Defense**:
RFC 9112 §6.3 provides guidance for intermediaries: *"If this is a request message, the server MUST respond with a 400 (Bad Request) status code and then close the connection."*

However, the critical flaw is this: *"A proxy or gateway MUST first remove the received Content-Length field and process the Transfer-Encoding as described below, before forwarding the message downstream."*

This requirement assumes proxies will correctly identify and handle conflicts—but implementation bugs and obfuscation techniques allow attackers to exploit differential parsing.

---

### 8. Obsolete Line Folding (RFC 9112 §5.2)

**Specification Statement**:
*"A server that receives obs-fold in a request message that is not within a message/http container MUST either reject the message by sending a 400 (Bad Request) status code, preferably with a representation explaining that obsolete line folding is unacceptable, or replace each received obs-fold with one or more SP octets prior to interpreting the field value or forwarding the message downstream."* (RFC 9112 §5.2)

**Security Implication**:
Obsolete line folding allows header values to span multiple lines by starting continuation lines with whitespace. While deprecated in RFC 7230 (2014) and maintained only for backward compatibility, many implementations still support it inconsistently.

**Attack Vectors**:
- **Header Obfuscation**: Folding headers across lines to evade security filters that use simple pattern matching.
- **Request Smuggling**: Different normalization of folded headers between intermediaries enables smuggling.
- **Filter Bypass**: Security tools scanning for malicious headers may fail to recognize folded versions.

**Real-World Examples**:
- **CVE-2025-32094**: HTTP/1.x OPTIONS requests with Expect: 100-continue and obsolete line folding caused discrepancies in Akamai server interpretation, enabling request smuggling.

**Spec-Based Defense**:
The specification acknowledges the security risk: *"Historically, HTTP header field values could be extended over multiple lines by preceding each extra line with at least one space or horizontal tab (obs-fold). This specification deprecates such line folding."*

Defense requires either:
1. Rejecting any request containing obs-fold (MUST option)
2. Normalizing by replacing folds with spaces (alternative option)

The problem: the "MUST either... or..." phrasing allows two different behaviors, creating inconsistency when intermediaries make different choices.

---

### 9. Unvalidated Header Reflection (RFC 9110 §10.1.1, §10.1.3)

**Specification Behavior**:
The spec defines headers like `Referer`, `User-Agent`, `X-Forwarded-For` (via common practice) that servers commonly reflect in responses, logs, or use for application logic.

*"The Referer header field allows the user agent to specify a URI reference for the resource from which the target URI was obtained."* (RFC 9110 §10.1.3)

**Security Implication**:
HTTP provides no sanitization requirements for reflected header values. Applications that echo headers into responses without encoding create XSS vectors.

**Attack Vectors**:
- **Reflected XSS via User-Agent**: Injecting JavaScript into User-Agent header that gets reflected in error pages.
- **Referer-based XSS**: Malicious Referer values reflected in analytics dashboards or logs.
- **X-Forwarded-For Injection**: SQL injection, XSS, or command injection when applications trust and reflect this header.
- **Log Injection**: Injecting newlines into headers to forge log entries for forensic evasion.

**Real-World Examples**:
- Many PHP error pages historically reflected User-Agent without escaping.
- Analytics platforms displaying Referer values have suffered XSS.
- Server monitoring tools parsing X-Forwarded-For from logs have been exploited.

**Spec-Based Defense**:
RFC 9110 §17.13 warns about information disclosure: *"The User-Agent header field often conveys information that might be of use to an attacker, such as the version numbers of various software components."*

However, the spec provides no requirement to sanitize reflected values. Defense must be implemented via:
1. Context-appropriate output encoding (HTML entity encoding, JavaScript escaping, etc.)
2. Content Security Policy (CSP) to mitigate XSS impact
3. Never trusting headers as safe data

---

### 10. Authorization Header Exposure (RFC 9110 §11.6.2)

**Specification Requirement**:
*"The Authorization header field allows a user agent to authenticate itself with an origin server."* (RFC 9110 §11.6.2)

*"A sender MUST NOT generate the userinfo subcomponent (and its '@' delimiter) in an http or https URI."* (RFC 9110 §4.2.4)

**Security Implication**:
While the spec mandates that credentials require confidential transport, it provides limited guidance on credential exposure risks in logging, caching, and intermediary contexts.

**Attack Vectors**:
- **Credential Leakage in Logs**: Authorization headers logged in plaintext on servers, proxies, or CDNs.
- **Cache Poisoning with Credentials**: Responses to authenticated requests accidentally cached and served to unauthenticated users.
- **Referer Leakage**: Credentials in URLs (deprecated but still occurs) leaked via Referer header.
- **Browser History Exposure**: Credentials in URLs stored in browser history.

**Real-World Examples**:
- GitHub tokens leaked in Travis CI logs due to verbose HTTP logging.
- CDN misconfigurations caching authenticated responses and serving to wrong users.
- API keys in URLs leaked through Referer headers when clicking external links.

**Spec-Based Defense**:
RFC 9110 §11.6.1 states: *"Any information transferred as part of an authentication challenge or credentials MUST be transmitted over a connection that provides confidentiality and integrity protections."*

Additionally: *"Authentication credentials are particularly sensitive; even when non-sensitive information is used to generate them, the authorization header field often contains a shared secret that, if exposed, could be used to compromise a user agent's account or access resources at any related origin server."*

Defense requires:
1. HTTPS mandatory for any authentication
2. Never including credentials in URLs
3. Preventing caching of authenticated responses (Cache-Control: no-store)
4. Sanitizing Authorization headers from logs

---

## Part III: HTTP Version-Specific Vulnerabilities

### 11. HTTP/2 Stream Multiplexing Attacks (RFC 9113 §5)

**Specification Behavior**:
HTTP/2 multiplexes multiple request/response exchanges ("streams") over a single TCP connection. Each stream has independent flow control and priority.

*"A single HTTP/2 connection can contain multiple concurrently open streams, with either endpoint interleaving frames from multiple streams."* (RFC 9113 §5)

**Security Implication**:
Stream multiplexing creates new DoS vectors and resource exhaustion attacks not possible in HTTP/1.1.

**Attack Vectors**:
- **Stream Reset Attacks (MadeYouReset)**: Attacker rapidly opens streams and immediately sends RST_STREAM frames, forcing server to allocate and deallocate resources repeatedly, exhausting CPU.
- **CONTINUATION Frame DoS**: Sending endless CONTINUATION frames without END_HEADERS flag to consume server memory.
- **Priority Tree Manipulation**: Crafting complex priority dependencies to consume server CPU during tree rebalancing.
- **Flow Control Exploitation**: Setting window size to zero to stall connections while keeping them open.

**Real-World Examples**:
- **MadeYouReset (2025)**: CVE assigned to HTTP/2 reset attack affecting major implementations. Coordinated disclosure by Tel Aviv University researchers via Akamai bug bounty.
- **HTTP/2 Rapid Reset (CVE-2023-44487)**: Widely exploited DoS attack using stream reset floods, affecting Google, Cloudflare, AWS, and others.

**Spec-Based Defense**:
RFC 9113 §10.5 addresses DoS: *"An endpoint that receives a HEADERS frame without the END_HEADERS flag set MUST buffer the contents of the header block until it receives CONTINUATION frames to complete the header block."*

However, the spec allows implementations flexibility: *"Endpoints MUST be prepared to receive and decode CONTINUATION frames after the header block fragment has been processed."*

The specification recommends: *"Implementations are encouraged to set SETTINGS_MAX_CONCURRENT_STREAMS to a value no smaller than 100."* But this is a SHOULD, not MUST.

Defense requires:
1. Setting conservative SETTINGS_MAX_CONCURRENT_STREAMS values
2. Implementing rate limits on RST_STREAM frames
3. Limiting CONTINUATION frame chains
4. Timeouts for incomplete header blocks

---

### 12. HPACK Header Compression Attacks (RFC 9113 §10.3, RFC 7541)

**Specification Behavior**:
HTTP/2 uses HPACK for header compression, maintaining a dynamic table of previously seen headers that both endpoints update based on header blocks exchanged.

*"HPACK relies on in-order transmission of compressed field sections."* (RFC 9114 §10.3)

**Security Implication**:
Stateful compression creates new attack vectors around decompression bombs, table poisoning, and side-channel attacks.

**Attack Vectors**:
- **Decompression Bomb**: Sending tiny compressed payload that expands to gigabytes when decompressed, exhausting server memory.
- **CRIME-style Attacks**: Using compression ratios as side-channel to infer authentication tokens by injecting known strings and measuring response sizes.
- **Table Poisoning**: Filling dynamic table with attacker-controlled entries to prevent legitimate headers from being compressed efficiently, causing DoS.

**Real-World Examples**:
- CRIME and BREACH attacks demonstrated compression-based side channels in TLS, similar principles apply to HPACK.
- Research has shown HPACK dynamic table manipulation can leak information across streams.

**Spec-Based Defense**:
RFC 9113 §10.3 requires: *"A receiver MUST terminate the connection with a connection error of type COMPRESSION_ERROR if it does not decompress a field block."*

The spec also mandates: *"A decoding error in a field block MUST be treated as a connection error of type COMPRESSION_ERROR."*

Defense requires:
1. Enforcing maximum header list size (SETTINGS_MAX_HEADER_LIST_SIZE)
2. Limiting dynamic table size
3. Detecting anomalous compression ratios
4. Avoiding shared compression contexts for sensitive and non-sensitive data

---

### 13. HTTP/3 and QUIC 0-RTT Replay Attacks (RFC 9114 §10.9)

**Specification Behavior**:
HTTP/3 leverages QUIC's 0-RTT capability, allowing clients to send application data in the first packet without waiting for handshake completion.

*"When 0-RTT is used, clients MUST only use it to carry idempotent requests."* (RFC 9114 §10.9)

**Security Implication**:
0-RTT data is not replay-protected by the transport layer. If replayed by an attacker, the server will process it as a legitimate request.

**Attack Vectors**:
- **Idempotence Violation**: If non-idempotent requests (POST, DELETE) are sent via 0-RTT, attackers can replay them to duplicate actions (e.g., duplicate purchases, repeated deletions).
- **Authentication Token Replay**: If authentication happens in 0-RTT data, tokens can be replayed before expiration.
- **State Manipulation**: Replaying stateful requests to cause resource exhaustion or logical errors.

**Real-World Examples**:
- Similar replay issues affected TLS 1.3 0-RTT adoption, with major sites disabling it for sensitive operations.
- Payment processing and financial transactions must never use 0-RTT due to replay risks.

**Spec-Based Defense**:
RFC 9114 §10.9 provides guidance: *"Clients MUST NOT automatically retry a request that uses any method or header fields that are not safe unless they have some means to know that the server can handle the replay safely."*

The spec continues: *"A client that constructs a request in 0-RTT data needs to ensure that it can be replayed safely."*

Defense requires:
1. Only allowing idempotent methods (GET, HEAD, OPTIONS, TRACE) in 0-RTT
2. Implementing application-layer replay protection (nonces, timestamps)
3. Using anti-replay tokens for sensitive operations
4. Clearly documenting which endpoints accept 0-RTT

---

### 14. HTTP/3 Connection Contamination (RFC 9114 §3.3)

**Specification Behavior**:
HTTP/3 removes HTTP/2's requirement that connection-scoped properties apply uniformly. Different streams can potentially target different hosts.

*"HTTP/3 relies on the QUIC transport protocol and its security features."* (RFC 9114 §10)

**Security Implication**:
Connection contamination occurs when a single HTTP/3 connection is reused for requests to multiple origins without proper isolation, potentially allowing cross-origin attacks.

**Attack Vectors**:
- **Cross-Origin Cookie Theft**: Attacker tricks client into reusing contaminated connection for sensitive domain, leaking cookies.
- **Authority Confusion**: Client sends request for origin A over connection established for origin B, bypassing same-origin policy checks.
- **Cache Poisoning Cross-Origin**: Responses for one origin cached and served for another origin sharing the connection.

**Real-World Examples**:
- PortSwigger research (2023) identified HTTP/3 connection contamination as an emerging threat.
- Similar connection reuse vulnerabilities affected HTTP/2 implementations historically.

**Spec-Based Defense**:
RFC 9114 §3.3 requires: *"The client MUST ensure that the selected QUIC connection satisfies the requirements for the request's origin."*

Defense requires:
1. Strict connection-to-origin binding
2. Certificate validation per-origin, not per-connection
3. Isolating cookies and authentication state by origin
4. Never reusing connections across different security contexts

---

## Part IV: Attack Technique Deep Dives

### 15. Request Smuggling: Specification Ambiguity as Attack Surface

**Root Cause in Specification**:
Request smuggling exploits inconsistencies in how different HTTP implementations parse message boundaries. The vulnerability exists because:

1. **Multiple framing methods exist**: Content-Length vs Transfer-Encoding vs connection close
2. **Conflict resolution is specified but not enforced uniformly**: *"the Transfer-Encoding overrides the Content-Length"* (RFC 9112 §6.3)
3. **Lenient parsing is encouraged**: *"In the interest of robustness..."* (RFC 9112 §2.2)
4. **Ambiguous edge cases**: Header obfuscation, whitespace handling, obsolete syntax

**Attack Taxonomy**:

**CL.TE (Content-Length front-end, Transfer-Encoding back-end)**:
```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
Front-end uses Content-Length (13 bytes = "0\r\n\r\nSMUGGLED"), back-end uses Transfer-Encoding (sees "0" chunk = end, then processes "SMUGGLED" as next request).

**TE.CL (Transfer-Encoding front-end, Content-Length back-end)**:
```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```
Front-end sees chunked encoding (8 bytes "SMUGGLED", then 0 = end), back-end uses Content-Length (3 bytes = "8\r\n"), treats "SMUGGLED\r\n0\r\n\r\n" as next request.

**TE.TE (Transfer-Encoding obfuscation)**:
```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5
SMUGGLED
0

```
Both endpoints support Transfer-Encoding but one ignores obfuscated variant.

**Real-World Impact**:
- **Bypass Authentication**: Smuggle request that inherits authenticated context of victim's request
- **Cache Poisoning**: Smuggle request that poisons cache entry for legitimate URL
- **Credential Hijacking**: Smuggle request that causes next user's request to be appended to response

**CVE Examples**:
- CVE-2025-32094: Obsolete line folding + OPTIONS method
- CVE-2023-25690: Apache mod_proxy encoding issues
- CVE-2020-11993: Apache mod_http2 logging memory corruption

**Specification Gap**:
RFC 9112 acknowledges the threat: *"Such a message might indicate an attempt to perform request smuggling and ought to be handled as an error."*

But uses "ought to" (not MUST) and allows intermediaries to "process" the message, creating room for exploitation.

---

### 16. Web Cache Poisoning: Unkeyed Input Exploitation

**Root Cause in Specification**:
HTTP caching specifications (RFC 9111) define how responses should be cached based on "cache keys"—typically method, URL, and Host header. Other headers are "unkeyed" by default.

*"A cache MUST NOT store a response unless the cache key can be calculated."* (RFC 9111 §4)

**Security Implication**:
Unkeyed inputs (like X-Forwarded-Host, Accept-Language, etc.) don't affect cache lookup but DO affect response generation. If a response containing attacker-controlled data gets cached, all subsequent requests with the same cache key receive the poisoned response.

**Attack Technique**:
1. Identify unkeyed input reflected in response (e.g., X-Forwarded-Host used to generate asset URLs)
2. Send request with malicious unkeyed header:
```
GET /page HTTP/1.1
Host: victim.com
X-Forwarded-Host: attacker.com
```
3. Application generates response with:
```html
<script src="https://attacker.com/malicious.js"></script>
```
4. Response gets cached with cache key based only on URL
5. All users requesting /page receive poisoned response with malicious script

**Exploitation Variants**:
- **Host Header Poisoning**: Manipulating Host header when it's reflected but not part of cache key
- **Header Injection**: Using headers like X-HTTP-Method-Override to bypass cache keys
- **Query Parameter Exploitation**: Reflected but unkeyed query params
- **Normalization Differentials**: Cache normalizes URL differently than origin server

**Real-World Examples**:
- PortSwigger's research identified thousands of vulnerable sites across major CDNs
- XSS through X-Forwarded-Host poisoning affecting popular CMSs
- Cache deception attacks leaking sensitive data

**Specification Gap**:
RFC 9111 §4.1 allows flexibility: *"The primary cache key consists of the request method and target URI."* But doesn't mandate inclusion of security-relevant headers like Host, allowing cache implementations to make unsafe assumptions.

---

### 17. Host Header Attacks: Protocol-Level Trust Assumption

**Root Cause in Specification**:
RFC 9112 §3.2 mandates: *"A client MUST send a Host header field in all HTTP/1.1 request messages."*

But provides no requirement for servers to validate it, and many applications use it for:
- Constructing absolute URLs (password resets, redirects)
- Virtual host routing decisions
- CORS origin validation
- API endpoint construction

**Attack Scenarios**:

**Password Reset Poisoning**:
```
POST /reset-password HTTP/1.1
Host: attacker.com
Content-Length: 29

email=victim@vulnerable.com
```
Application generates reset email:
```
Reset your password: https://attacker.com/reset?token=xyz123
```
Victim clicks link, attacker steals token.

**Virtual Host Confusion**:
```
GET /admin HTTP/1.1
Host: localhost
```
Bypasses external access restrictions if application routes based on Host header without validation.

**Web Cache Poisoning**:
```
GET /page HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: attacker.com
```
If application prefers X-Forwarded-Host over Host and generates:
```html
<link rel="canonical" href="https://attacker.com/page">
```
This gets cached for legitimate users.

**Real-World Examples**:
- Documented in OWASP Web Security Testing Guide
- Affects major CMSs and frameworks that auto-generate URLs
- Web cache poisoning via Host header identified in multiple bug bounty programs

**Specification Gap**:
The spec requires Host header but doesn't mandate validation. RFC 9110 §4.2.1 only prohibits empty hosts: *"A sender MUST NOT generate an 'http' or 'https' URI with an empty host."*

No requirement exists to verify Host matches expected server hostname, leaving this to application layer.

---

### 18. Client-Side Desync (CSD) Attacks

**Root Cause in Specification**:
Client-side desync vulnerabilities occur when web servers fail to correctly process the Content-Length of POST requests, causing the victim's browser—not an intermediary—to desynchronize its own connection to the website.

**Specification Gap**:
RFC 9112 §6.3 requires servers to read the full message body as indicated by Content-Length, but doesn't specify what must happen when servers respond before reading the complete body. This implementation flexibility creates CSD vectors.

**Attack Mechanism**:
Web servers can sometimes be encouraged to respond to POST requests without reading in the body. If they subsequently allow the browser to reuse the same connection for additional requests, this results in a client-side desync vulnerability.

**Detection Technique**:
Send a request where the specified Content-Length is longer than the actual body:
```http
POST /vulnerable-endpoint HTTP/1.1
Host: vulnerable-website.com
Content-Length: 100

x=1
```

If the request hangs or times out, the server is waiting for the remaining bytes (not vulnerable). If you get an immediate response, you've potentially found a CSD vector.

**Exploitation Steps**:
1. **Identify CSD vector**: Find endpoint that responds without reading full body
2. **Desync the connection**: Send incomplete POST request to desynchronize browser's connection
3. **Poison browser's connection pool**: Next request from browser gets prepended with desync payload
4. **Trigger victim's request**: Social engineer victim to navigate to attacker-controlled page that triggers malicious request

**Attack Example**:
```http
POST /vulnerable HTTP/1.1
Host: victim.com
Content-Length: 800

x=1
GET /admin HTTP/1.1
Foo: bar
```

Browser sends above, server responds immediately without reading 800 bytes. Browser believes 799 bytes remain. When browser sends next request, it gets appended to the unread portion, causing the server to process the attacker's smuggled GET /admin.

**Real-World Impact**:
- **XSS via reflected content**: Smuggled request contains XSS payload that gets reflected in victim's next request
- **Cache poisoning**: Poison browser's cache with attacker-controlled responses
- **Account takeover**: Smuggle requests that modify account details

**Research Source**:
PortSwigger's "Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling" (Black Hat USA 2022, DEF CON 30)

**Spec-Based Defense**:
RFC 9112 doesn't mandate reading full body before responding, creating this vulnerability class. Defense requires:
1. Always read full Content-Length before responding to POST requests
2. Close connections after responding to potentially desynchronized requests
3. Implement timeouts for partial body reads
4. Validate Content-Length matches actual body size

---

### 19. Pause-Based Desync Attacks

**Specification Behavior**:
HTTP/1.1 allows persistent connections where multiple requests are sent over the same TCP connection. Servers must carefully manage connection state between requests.

**Vulnerability Mechanism**:
Pause-based desync affects servers (Apache, Varnish) that process chunks differently when the chunk size declaration and chunk body are received in separate TCP packets. By strategically timing packet delivery, attackers can cause parsing desynchronization.

**Attack Technique**:
```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: chunked

1
[PAUSE - send in separate packet]
A
0

GET /admin HTTP/1.1
Host: vulnerable.com
```

By pausing between sending the chunk size declaration "1" and the actual chunk data "A", some servers become confused about request boundaries, enabling smuggling.

**Why It Works**:
RFC 9112 §7.1 specifies chunked encoding format but doesn't mandate timing requirements for chunk data arrival. Some implementations enter vulnerable states when chunk metadata and data arrive in separate network packets due to Nagle's algorithm interactions.

**Exploitation Variants**:
- **Server-side smuggling**: Traditional CL.TE/TE.CL exploitation using pauses
- **Client-side desync**: Trigger browser-side desyncs using pause timing
- **Cache poisoning**: Poison CDN caches by timing chunk delivery

**Single-Packet Attack**:
James Kettle's "Smashing the State Machine" research (PortSwigger Top 10 2023) combined Nagle's algorithm with HTTP/2 to create single-packet attacks where 20-30 conflicting requests arrive simultaneously, overwhelming state machine validation.

**Specification Gap**:
RFC 9112 §7.1 defines chunked encoding syntax but provides no timing guarantees or requirements for when chunk data must arrive after chunk size declaration.

**Defense**:
1. Implement strict timing requirements for chunk data arrival
2. Buffer and validate complete chunks before processing
3. Reject requests with suspicious timing patterns
4. Disable connection reuse for chunked requests (reduces performance)

---

### 20. HTTP/2 Downgrade Attacks (H2.TE and H2.CL)

**Root Cause in Specification**:
HTTP/2 downgrading occurs when front-end servers speak HTTP/2 with clients but rewrite requests into HTTP/1.1 before forwarding to back-end servers. This protocol translation creates three different ways to specify request length, enabling smuggling.

**Specification Context**:
- RFC 9113 (HTTP/2) uses frame length for message boundaries
- RFC 9112 (HTTP/1.1) uses Content-Length or Transfer-Encoding
- Front-end trusts HTTP/2 frame length; back-end receives downgraded HTTP/1.1 with CL/TE headers

**Attack Taxonomy**:

**H2.TE (HTTP/2 front-end, Transfer-Encoding back-end)**:
```http
:method POST
:path /
:authority vulnerable.com
transfer-encoding chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
```

Front-end uses HTTP/2 frame length, back-end uses Transfer-Encoding: chunked and processes "GET /admin" as next request.

**H2.CL (HTTP/2 front-end, Content-Length back-end)**:
```http
:method POST
:path /
:authority vulnerable.com
content-length 4

SMUGGLED
```

Front-end reads full frame, back-end reads only 4 bytes based on Content-Length, treating "GLED" as the start of next request.

**Why HTTP/2 Makes It Worse**:
1. **No ambiguity in HTTP/2**: Message length is always clear via frame length
2. **Downgrade introduces ambiguity**: Translation to HTTP/1.1 reintroduces CL/TE confusion
3. **Pseudo-headers bypass validation**: HTTP/2 pseudo-headers (`:method`, `:path`) can bypass front-end validation that only checks HTTP/1.1 format
4. **Header injection via HPACK**: Compressed headers in HTTP/2 can inject values that bypass HTTP/1.1 parsers

**HTTP/2 Header Injection**:
Attackers can inject HTTP/1.1 headers via HTTP/2 pseudo-headers:
```http
:method POST
:path /
:authority vulnerable.com
:header-name foo\r\nTransfer-Encoding: chunked
```

When downgraded to HTTP/1.1, this becomes:
```http
POST / HTTP/1.1
Host: vulnerable.com
header-name: foo
Transfer-Encoding: chunked
```

**Real-World Examples**:
- James Kettle's "HTTP/2: The Sequel is Always Worse" (DEF CON 29) documented these attacks
- Thousands of vulnerable downgrading proxies identified across major CDNs
- Affected HAProxy, nginx, Traefik, and other popular reverse proxies

**Specification Gap**:
Neither RFC 9113 nor RFC 9112 address the security implications of protocol downgrading. The translation process itself creates vulnerabilities.

**Defense**:
1. **End-to-end HTTP/2**: Avoid downgrading; use HTTP/2 to back-end
2. **Strip dangerous headers**: Remove Content-Length and Transfer-Encoding from HTTP/2 requests before downgrading
3. **Header validation**: Validate all headers in HTTP/2 requests before translation
4. **Strict downgrade rules**: Implement secure downgrade translation that prevents smuggling

---

### 21. H2C Smuggling

**Specification Background**:
H2C (HTTP/2 Cleartext) is HTTP/2 without TLS. RFC 9113 §3.4 defines the h2c upgrade mechanism:
```http
GET / HTTP/1.1
Host: server.example.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: <base64url encoding of HTTP/2 SETTINGS payload>
```

Server responds with `101 Switching Protocols`, and connection switches to HTTP/2.

**Attack Mechanism**:
H2C smuggling exploits misconfigured front-ends that forward the `Upgrade: h2c` header to back-end servers that support cleartext HTTP/2. This allows attackers to tunnel raw HTTP/2 frames through edge security that only validated HTTP/1.1.

**Why It's Dangerous**:
1. **Bypasses header normalization**: Front-end normalizes HTTP/1.1 but doesn't process HTTP/2 frames
2. **Evades WAF rules**: WAF inspects HTTP/1.1 but tunneled HTTP/2 frames aren't inspected
3. **TLS termination bypass**: Even when TLS terminates at edge, h2c allows cleartext HTTP/2 to back-end
4. **Direct back-end access**: Attacker speaks directly to back-end in HTTP/2 format

**Attack Example**:
```http
GET / HTTP/1.1
Host: vulnerable.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA

[Followed by raw HTTP/2 frames containing malicious requests]
```

If front-end forwards these headers to h2c-capable back-end:
```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: h2c

[Back-end now speaks HTTP/2 directly with attacker]
```

**Vulnerable Configurations**:
- **HAProxy**: Default configuration forwards Upgrade headers
- **Traefik**: Forwards h2c upgrade headers by default
- **Nuster**: Similar default behavior

**Real-World Impact**:
- Bypass access controls by tunneling admin requests
- Evade rate limiting and security policies
- Inject unrestricted HTTP/2 traffic to back-end
- Exploit back-end HTTP/2 implementation bugs

**Specification Gap**:
RFC 9113 §3.4 defines h2c upgrade for direct client-server communication but doesn't address security implications when intermediaries are involved.

**Defense**:
1. **Strip Upgrade headers**: Remove or hard-code Upgrade header at edge (except for WebSockets)
2. **Disable h2c on back-end**: Only accept TLS HTTP/2 (h2), not cleartext (h2c)
3. **Whitelist Upgrade targets**: Only allow Upgrade: websocket, reject Upgrade: h2c
4. **Monitor for h2c**: Alert on h2c upgrade attempts in production

---

### 22. HTTP Request Tunneling

**Specification Context**:
HTTP/2 streams should only ever contain a single request and response. RFC 9113 §8.1 states each stream is an independent bidirectional sequence of frames.

**Vulnerability Mechanism**:
Request tunneling exploits the ability to send a request that elicits two responses from the back-end while the front-end only expects one. This "hides" the second request and response from front-end security controls.

**Attack Technique**:
Send an HTTP/2 request containing a complete HTTP/1.1 request in the body:
```http
:method POST
:path /comment
:authority vulnerable.com
content-type application/x-www-form-urlencoded

comment=x
GET /admin HTTP/1.1
Host: vulnerable.com
Foo: bar
```

When downgraded to HTTP/1.1 and sent to back-end:
```http
POST /comment HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded

comment=x
GET /admin HTTP/1.1
Host: vulnerable.com
Foo: bar
```

If back-end processes the body as a second request (due to smuggling), it returns two responses. Front-end receives first response for POST /comment, second response (for GET /admin) is "tunneled" and may:
- Appear in response body as HTTP/1.1 formatted text
- Be cached separately
- Cause response queue poisoning

**Detection**:
If you receive an HTTP/2 response with what appears to be an HTTP/1.1 response in the body, you've successfully tunneled a second request:
```http
HTTP/1.1 200 OK
Content-Type: text/html

HTTP/1.1 200 OK
Content-Type: application/json

{"admin": "secret_data"}
```

**Exploitation Scenarios**:
- **Bypass path restrictions**: Tunnel requests to /admin when front-end blocks direct access
- **Evade authentication**: Tunnel authenticated requests through unauthenticated endpoints
- **Web cache poisoning**: Tunnel requests that poison cache with attacker-controlled content

**Real-World Examples**:
- PortSwigger research identified request tunneling across major CDNs
- Used to bypass front-end access controls in enterprise applications
- Combined with cache poisoning for widespread XSS

**Specification Gap**:
RFC 9113 assumes one request per stream but doesn't prevent back-end servers from processing request bodies as additional requests during HTTP/2→HTTP/1.1 downgrading.

**Defense**:
1. **Never process request bodies as HTTP**: Validate content-type and reject if it contains HTTP syntax
2. **Strict stream isolation**: Ensure back-end only returns one response per HTTP/2 stream
3. **Response validation**: Alert if response body contains HTTP response patterns
4. **End-to-end HTTP/2**: Avoid downgrading to eliminate vulnerability

---

### 23. Response Queue Poisoning

**Root Cause in Specification**:
RFC 9112 §6 requires HTTP/1.1 implementations to correctly match responses to requests on persistent connections. However, request smuggling can desynchronize this matching, causing catastrophic response misattribution.

**Attack Mechanism**:
Response queue poisoning occurs when a front-end server starts mapping responses from the back-end to the wrong requests. This means all users of the same front-end/back-end connection persistently receive responses intended for other users.

**Why It's Devastating**:
Unlike typical request smuggling that affects individual requests, response queue poisoning creates a persistent state where the queue is "shifted"—all subsequent users get wrong responses until the connection closes.

**Attack Requirements**:
1. **Persistent connections**: TCP connection between front-end and back-end must be reused
2. **Complete request smuggling**: Must smuggle a complete, standalone request
3. **Connection survival**: Attack must not cause connection closure

**Attack Example (H2.TE variant)**:
```http
:method POST
:path /x
:authority vulnerable.com
transfer-encoding chunked

0

GET /account HTTP/1.1
Host: vulnerable.com
```

**Attack Flow**:
1. Attacker sends smuggled request containing "GET /account"
2. Back-end processes two requests: POST /x and GET /account
3. Back-end returns two responses
4. Front-end expects one response, maps first response to attacker's HTTP/2 stream
5. Second response (containing victim's account data) waits in queue
6. Victim sends unrelated request (e.g., GET /static/logo.png)
7. Front-end maps second response (account data) to victim's request, but delivers it to the ATTACKER who is still listening
8. Queue is now permanently shifted—all subsequent responses go to wrong requesters

**Exploitation**:
Using Burp Intruder or similar tools, attackers automate reissuing requests to capture responses intended for different victims:
```
Request 1 (attacker) → Response A (intended for victim 1)
Request 2 (attacker) → Response B (intended for victim 2)
Request 3 (attacker) → Response C (intended for victim 3)
```

Each response may contain:
- Session tokens
- CSRF tokens
- Personal information
- API keys
- Authentication cookies

**Real-World Impact**:
- **Mass credential theft**: Capture session tokens for dozens of users
- **Account takeover**: Use stolen tokens to access victim accounts
- **Data exfiltration**: Leak sensitive business data across users
- **Compliance violations**: Massive privacy breach (GDPR, CCPA)

**PortSwigger Labs**:
"Response queue poisoning via H2.TE request smuggling" lab demonstrates this attack.

**Specification Gap**:
RFC 9112 assumes request/response matching is reliable but provides no mechanism to detect or recover from queue poisoning caused by smuggled requests.

**Defense**:
1. **Prevent request smuggling**: Eliminate underlying smuggling vulnerabilities
2. **Connection isolation**: Use dedicated connections per user/session
3. **Response validation**: Match response characteristics to expected request
4. **Short connection lifetimes**: Limit requests per connection to minimize poisoning window
5. **Monitoring**: Alert on unexpected response patterns or timing anomalies

---

### 24. HTTP Parameter Pollution (HPP)

**Specification Ambiguity**:
Current HTTP standards (RFC 9110, RFC 9112) do not provide guidance on how to interpret multiple input parameters with the same name. RFC 3986 §3.4 defines query syntax but doesn't specify handling of duplicate parameters.

**Root Cause**:
Individual web technologies parse duplicate parameters differently:
- **PHP/Apache**: Uses last occurrence (`?param=first&param=second` → `second`)
- **ASP.NET/IIS**: Uses concatenated with comma (`?param=first&param=second` → `first,second`)
- **JSP/Tomcat**: Uses first occurrence (`?param=first&param=second` → `first`)
- **Node.js/Express**: Returns array (`?param=first&param=second` → `['first', 'second']`)

**Attack Mechanism**:
Exploit differential parsing between front-end security filters and back-end application:

**Example 1: WAF Bypass via Server-Side HPP**
```http
GET /transfer?amount=1000&to=attacker&amount=100&to=victim HTTP/1.1
Host: bank.com
```

- WAF sees first occurrence: `amount=1000&to=attacker` (flags as suspicious high amount)
- Back-end (PHP) uses last occurrence: `amount=100&to=victim` (bypasses validation)

**Example 2: Client-Side HPP (Reflected XSS)**
```http
GET /search?query=<script>&query=alert(1)</script> HTTP/1.1
Host: vulnerable.com
```

Application reflects both parameters in response:
```html
<h1>Search results for <script>&query=alert(1)</script></h1>
```

Browser executes JavaScript.

**Example 3: Authentication Bypass**
```http
POST /login HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded

user=admin&user=guest&pass=adminpass
```

If authentication checks first occurrence (`user=admin`) but session creation uses last occurrence (`user=guest`), attacker bypasses authentication.

**Exploitation Variants**:
- **Authorization bypass**: Manipulate role/permission parameters
- **CSRF protection bypass**: Pollute CSRF token validation
- **Open redirect**: Override redirect URL parameters
- **SQL injection**: Pollute parameters used in SQL queries
- **SSRF**: Override URL parameters in server-side requests

**Real-World Examples**:
- PayPal HPP vulnerability allowed payment amount manipulation
- Twitter HPP enabled unauthorized OAuth token generation
- Multiple CMS platforms vulnerable to HPP-based authentication bypass

**Specification Gap**:
RFC 9110 §6.4.1 defines query component but doesn't mandate duplicate parameter handling, leaving implementations with incompatible behaviors.

**Defense**:
1. **Canonicalize parameters**: Always use consistent parsing (first, last, or reject duplicates)
2. **Validate all occurrences**: If allowing duplicates, validate ALL values, not just first/last
3. **Reject duplicates**: Configure application to reject requests with duplicate parameters
4. **Explicit arrays**: Use explicit array syntax (e.g., `param[]=value1&param[]=value2`)
5. **WAF consistency**: Ensure WAF and application parse identically

---

### 25. Web Cache Deception

**Root Cause in Specification**:
RFC 9111 (HTTP Caching) defines cache key calculation but doesn't mandate URL normalization methods. Discrepancies between cache and origin server normalization create exploitation vectors.

**Attack Mechanism**:
Web cache deception exploits path normalization differences to trick caches into storing dynamic, sensitive responses as if they were static resources.

**Path Normalization Confusion**:

**Example 1: Delimiter Discrepancy**
```http
GET /account/settings.css HTTP/1.1
Host: vulnerable.com
```

- **Cache behavior**: Sees `.css` extension, treats as static, caches response
- **Origin behavior**: Ignores `.css`, processes `/account/settings`, returns sensitive account data

Cache stores sensitive data, attacker retrieves it later.

**Example 2: Encoded Delimiters**
```http
GET /account%2Fdata.js HTTP/1.1
Host: vulnerable.com
```

- **Cache**: Doesn't decode `%2F`, treats whole path as static file ending in `.js`
- **Origin**: Decodes `%2F` to `/`, processes as `/account/data`

**Example 3: Path Traversal**
```http
GET /account/..%2Fstatic%2Flogo.png HTTP/1.1
Host: vulnerable.com
```

- **Cache**: Normalizes to `/static/logo.png`, caches
- **Origin**: Processes as `/account/..%2Fstatic%2Flogo.png` → `/account`

**Attack Flow**:
1. Attacker identifies normalization discrepancy
2. Attacker crafts URL that cache sees as static, origin sees as dynamic
3. Attacker tricks victim into visiting crafted URL
4. Victim's browser sends request with authentication cookies
5. Origin returns victim's sensitive data
6. Cache stores response (thinks it's static logo.png)
7. Attacker retrieves cached response (no auth needed)

**PortSwigger Research**:
"Gotta cache 'em all: bending the rules of web cache exploitation" documented advanced cache deception techniques including:
- Delimiter confusion (`;`, `#`, `?`)
- Encoding differentials
- Fat GET requests (oversized URLs)
- Static extension smuggling

**Real-World Impact**:
- **Private data leakage**: Cache stores PII, API keys, session data
- **Compliance violations**: GDPR/CCPA violations from cached personal data
- **Credential theft**: Cached authentication tokens
- **Business logic bypass**: Cache poisoning bypasses access controls

**Specification Gaps**:
1. RFC 9110 §4.2 defines URI syntax but not normalization requirements
2. RFC 9111 §4 defines cache keys but doesn't mandate including security-relevant headers
3. No standard for path normalization between cache and origin

**Defense**:
1. **Consistent normalization**: Ensure cache and origin normalize identically
2. **Cache-Control headers**: Mark dynamic content with `Cache-Control: no-store, private`
3. **Validator headers**: Use `Vary` header to include security-relevant headers in cache key
4. **Content-Type validation**: Cache only if Content-Type matches file extension
5. **Path allowlist**: Only cache explicitly approved static paths
6. **Monitor anomalies**: Alert on cached responses with authentication cookies

---

### 26. Transfer-Encoding Obfuscation Techniques

**Specification Context**:
RFC 9112 §6.3 states that if both Content-Length and Transfer-Encoding are present, "the Transfer-Encoding overrides the Content-Length." However, servers that can be induced NOT to process Transfer-Encoding create smuggling vulnerabilities.

**Core Vulnerability**:
Some servers support Transfer-Encoding but can be tricked into ignoring it through header obfuscation, causing TE.TE vulnerabilities where both front-end and back-end support TE but one is deceived.

**Obfuscation Techniques Catalog**:

**1. Whitespace Variations**
```http
Transfer-Encoding: chunked           (standard)
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding:  chunked          (extra space after colon)
Transfer-Encoding:\tchunked          (tab instead of space)
 Transfer-Encoding: chunked          (leading space)
Transfer-Encoding: chunked           (trailing whitespace)
```

**2. Case Variations**
```http
Transfer-Encoding: chunked
transfer-encoding: chunked
Transfer-encoding: chunked
TRANSFER-ENCODING: CHUNKED
```

**3. Value Obfuscation**
```http
Transfer-Encoding: chunked
Transfer-Encoding: xchunked
Transfer-Encoding: chunked, identity
Transfer-Encoding: identity, chunked
Transfer-Encoding: chunked;oops
Transfer-Encoding: chunked[tab]
Transfer-Encoding: chu nked
```

**4. Duplicate Headers**
```http
Transfer-Encoding: chunked
Transfer-Encoding: identity
```
Some servers use first, some use last, some concatenate.

**5. Line Folding (Obsolete)**
```http
Transfer-Encoding:\r\n chunked
```
Obsolete obs-fold syntax still parsed by some implementations.

**6. Non-Standard Delimiters**
```http
Transfer-Encoding: chunked\r\n Transfer-Encoding: cow
```

**7. Vertical Tab / Form Feed**
```http
Transfer-Encoding:\x0Bchunked
Transfer-Encoding:\x0Cchunked
```

**8. Null Bytes**
```http
Transfer-Encoding: chunked\x00
Transfer-Encoding: \x00chunked
```

**Exploitation Example**:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

96
GET /admin HTTP/1.1
Host: vulnerable.com
Content-Length: 10

x=
0

```

- Front-end: Sees both TE headers, uses chunked (reads 96 bytes + 0 terminator)
- Back-end: Second TE header is obfuscated (`x` is not `chunked`), falls back to CL (reads 4 bytes)
- Result: TE.CL smuggling—"GET /admin..." becomes next request

**Automated Detection**:
Burp Suite's HTTP Request Smuggler extension tests multiple obfuscation variants:
```
Transfer-Encoding: chunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked,chunked
Transfer-Encoding: chunked, cow
Transfer-Encoding: chunked;oops
...and 20+ more variants
```

**Specification Gap**:
RFC 9112 §4 defines field-name syntax strictly but §2.2 encourages lenient parsing: *"recipients SHOULD parse defensively."* This contradiction enables obfuscation attacks.

**Defense**:
1. **Strict TE validation**: Only accept exact "Transfer-Encoding: chunked" syntax
2. **Reject obfuscations**: Error on any TE header variation
3. **Normalize headers**: Strip whitespace, lowercase field names before processing
4. **Single TE policy**: Reject requests with duplicate Transfer-Encoding headers
5. **Regular testing**: Test with Burp Suite's smuggler extension to identify obfuscation vulnerabilities

---

### 27. HTTP Pipelining Exploits

**Specification Background**:
RFC 9112 §9.3.2 allows HTTP pipelining—sending multiple requests over a single connection without waiting for responses:
```http
GET /page1 HTTP/1.1\r\n...
GET /page2 HTTP/1.1\r\n...
GET /page3 HTTP/1.1\r\n...
```

Server must respond in same order (FIFO).

**Security Implications**:

**1. DoS via Resource Exhaustion**
Attacker pipelines hundreds of requests instantly:
```http
GET /expensive-operation HTTP/1.1\r\n...[x1000]
```
Server must process all before responding, consuming CPU/memory. Unlike normal requests, server can't distinguish between legitimate pipelining and resource exhaustion attack.

**2. Request Smuggling Confusion**
Pipelining creates ambiguity with request smuggling detection. Legitimate pipelining looks similar to smuggling:

**Legitimate pipelining:**
```http
GET /page1 HTTP/1.1
Host: example.com

GET /page2 HTTP/1.1
Host: example.com
```

**Request smuggling:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 5

smugGET /admin HTTP/1.1
```

Detection tools may generate false positives when pipelining is enabled.

**3. Cache Poisoning**
Pipeline multiple requests with same cache key but different Host headers:
```http
GET / HTTP/1.1
Host: legitimate.com

GET / HTTP/1.1
Host: attacker.com
```

If cache keys on URL only (not Host), second response may get cached for legitimate.com.

**4. Timing-Based Attacks**
Pipelining masks timing side-channels. Attacker sends:
```http
GET /user/admin HTTP/1.1\r\n
GET /user/nonexistent HTTP/1.1\r\n [x100]
```

Without pipelining, slow response to first request reveals admin exists. With pipelining, all responses arrive together, hiding timing information from server's perspective but attacker can still measure which individual response was slow.

**5. Meris Botnet DDoS**
The Meris botnet uses HTTP pipelining to amplify DDoS attacks, sending hundreds of requests per connection to maximize attack throughput.

**Why Most Browsers Disabled It**:
Modern browsers (Chrome, Firefox, Safari) disabled HTTP pipelining by default due to:
- Incompatible server implementations
- Request smuggling risks
- Cache poisoning vectors
- DoS amplification

**Specification Gap**:
RFC 9112 §9.3.2 permits pipelining but acknowledges: *"Many implementations do not support pipelining."* The optional nature creates security inconsistency.

**Defense**:
1. **Disable pipelining**: Most servers disable by default; keep it disabled
2. **Rate limiting**: Limit requests per connection regardless of pipelining
3. **Connection limits**: Set max requests per connection (e.g., 100)
4. **Early detection**: Monitor for rapid sequential requests without waiting for responses
5. **Timeouts**: Implement strict timeouts for pipelined request processing

---

## Part V: Latest CVEs and Attack Cases (2024-2025)

### CVE-2025-32094: HTTP Request Smuggling via OPTIONS + Obsolete Line Folding

**Affected Systems**: Akamai edge servers
**Disclosure**: March 2025
**Specification Violation**: RFC 9112 §5.2 (obs-fold), RFC 9112 §3.7 (OPTIONS method)

**Attack Mechanism**:
Combining HTTP/1.x OPTIONS request with `Expect: 100-continue` header and obsolete line folding created parsing discrepancy between two in-path Akamai servers.

**RFC Connection**:
- Obsolete line folding (obs-fold) deprecated in RFC 7230 but still parsed by many implementations
- RFC 9112 §5.2 allows two handling options: reject or normalize—Akamai servers chose different options
- OPTIONS method with Expect header created edge case in request processing pipeline

**Impact**: Request smuggling enabling authentication bypass, cache poisoning

---

### CVE-2023-25690: Apache mod_proxy Encoding Bypass

**Affected**: Apache HTTP Server 2.4.59 and earlier
**Specification Connection**: RFC 9110 §4.2.1 (URI encoding)

**Attack Mechanism**:
Encoding problems in mod_proxy allowed request URLs with incorrect encoding to be sent to backend services, potentially bypassing authentication.

**RFC Gap**: While RFC 9110 defines URI encoding, it doesn't mandate how proxies should normalize or validate encoding before forwarding, allowing implementation-specific handling.

---

### CVE-2024-24549: Apache Tomcat HTTP/2 Header Handling DoS

**Affected**: Apache Tomcat 11.0.0-M1 through 11.0.0-M16, 10.1.0-M1 through 10.1.18, 9.0.0-M1 through 9.0.85, 8.5.0 through 8.5.98
**Severity**: Important
**Specification Connection**: RFC 9113 §8 (HTTP/2 streams)

**Attack Mechanism**:
When processing an HTTP/2 request that exceeded any of the configured limits for headers, the associated HTTP/2 stream was not reset until after all of the headers had been processed. This allows an attacker to cause Denial of Service by sending requests with excessive headers.

**Impact**: Denial of Service (not request/response mix-up)

**Defense**: Upgrade to Apache Tomcat version 11.0.0-M17, 10.1.19, 9.0.86 or 8.5.99

**RFC Gap**: RFC 9113 §6.5.2 defines header size limits but doesn't mandate when to reset streams, allowing delayed reset behavior that enables DoS.

---

### MadeYouReset (CVE-2025-8671): HTTP/2 DoS via Rapid RST_STREAM

**Year**: 2025 (disclosed August 13, 2025)
**Specification Connection**: RFC 9113 §5.4 (RST_STREAM)

**Attack Mechanism**:
Attacker rapidly opens streams and immediately sends RST_STREAM frames, causing server CPU exhaustion through repeated resource allocation/deallocation cycles.

**RFC Gap**: RFC 9113 §5.4 defines RST_STREAM behavior but doesn't mandate rate limiting or set minimum interval between resets, allowing this attack pattern.

---

### HTTP/2 Rapid Reset (CVE-2023-44487)

**Year**: 2023
**Affected**: Google, Cloudflare, AWS, and most HTTP/2 implementations
**Specification Connection**: RFC 9113 §5.4

**Attack Mechanism**: Similar to MadeYouReset—flood of stream resets exhausting server resources.

**Mitigation**: Vendors implemented rate limiting on RST_STREAM frames, which the RFC doesn't require but doesn't prohibit.

---

### CVE-2025-66373: HTTP Request Smuggling Due to Invalid Chunked Body Size

**Year**: 2025
**Affected**: Akamai and various web servers
**Specification Connection**: RFC 9112 §7.1 (chunked encoding)

**Attack Mechanism**:
Invalid chunk size declarations in Transfer-Encoding: chunked requests cause parsing discrepancies. When chunk size contains invalid characters or exceeds expected limits, different implementations handle the error differently—some reject, some ignore, some attempt recovery.

**Example Payload**:
```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: chunked

FFFFFFFFFFFFFFFF
malicious_data_here
0

GET /admin HTTP/1.1
```

**RFC Gap**:
RFC 9112 §7.1 defines chunk-size as 1*HEXDIG but doesn't mandate maximum size or specify error handling for oversized/invalid values. Different implementations:
- Some reject oversized chunks immediately
- Some parse modulo (FFFFFFFFFFFFFFFF wraps to small value)
- Some ignore and fall back to connection close

**Impact**: Request smuggling, DoS via resource exhaustion, cache poisoning

**Defense**: Enforce reasonable chunk size limits (e.g., max 16MB), reject invalid hex characters, consistent error handling

---

### CVE-2020-11993: Apache HTTP/2 Module Logging Memory Corruption

**Year**: 2020
**Affected**: Apache HTTP Server 2.4.20 through 2.4.43 (mod_http2)
**Severity**: Moderate
**Specification Connection**: RFC 9113 (HTTP/2)

**Attack Mechanism**:
When trace/debug was enabled for the HTTP/2 module (mod_http2), on certain traffic edge patterns, logging statements were made on the wrong connection, causing concurrent use of memory pools. This is NOT a request smuggling vulnerability.

**Exploitation**:
1. Attacker sends specially crafted HTTP/2 traffic patterns
2. If trace/debug logging is enabled for mod_http2, logging occurs on incorrect connection
3. Concurrent memory pool access causes memory corruption

**Impact**: Memory corruption, potential DoS

**Mitigation**:
- Configure LogLevel of mod_http2 above "info" level
- Upgrade to Apache 2.4.44 or later
- Disable trace/debug logging in production

**Note**: This is a mod_http2 logging issue, NOT a mod_proxy vulnerability. The vulnerability only affects systems with debug/trace logging enabled.

---

### SMTP Smuggling (2024 Research)

**Year**: 2024
**Context**: While primarily SMTP-focused, this research demonstrated cross-protocol smuggling principles applicable to HTTP

**Technique**:
Exploits different interpretations of message end-of-data sequences (similar to HTTP's CRLF ambiguities). Different SMTP servers interpret `\r.\r\n` vs `\n.\n` differently, enabling message smuggling.

**HTTP Parallel**:
Same principle applies to HTTP with CRLF variations, demonstrating that protocol smuggling is a systemic issue across text-based protocols sharing similar framing mechanisms.

**PortSwigger Top 10 2024**: This technique was nominated and demonstrated cross-protocol applicability of desync attack principles.

---

### Browser-Powered Request Smuggling (2022-2024 Evolution)

**Timeline**:
- 2019: HTTP Desync Attacks Reborn (server-side smuggling)
- 2022: Browser-Powered Desync (client-side)
- 2023: Pause-based desync
- 2024: Continued refinement and new variants

**Evolution**:
The attack surface evolved from pure server-side smuggling to browser-based exploitation, demonstrating how HTTP's parsing flexibility creates vulnerabilities across the entire request chain—from client through intermediaries to origin.

**PortSwigger Top 10**: "Smashing the state machine" (2023) combined race conditions with desync techniques, showing how timing attacks amplify parsing ambiguities.

**Significance**:
These aren't isolated CVEs but represent fundamental specification design choices creating entire attack classes. Each new variant exploits the same root causes: lenient parsing, multiple framing methods, and lack of strict validation requirements in RFCs.

---

## Part VI: Comprehensive Attack-Spec-Defense Mapping

| Attack Type | Exploited Spec Behavior | RFC Reference | Specification Gap | Defense Mechanism |
|-------------|------------------------|---------------|-------------------|-------------------|
| Request Smuggling (CL.TE) | Content-Length + Transfer-Encoding conflict | RFC 9112 §6.3 | Uses "ought to" not MUST; allows lenient parsing | Reject requests with both headers; strict parsing |
| Request Smuggling (TE.TE) | Transfer-Encoding obfuscation tolerance | RFC 9112 §6.3 | Allows implementation-specific handling of malformed headers | Reject any Transfer-Encoding not exactly "chunked" |
| Response Splitting | CRLF injection in headers | RFC 9112 §5, §11.1 | No MUST requirement to validate; "SHOULD reject" | Reject any header value containing CR or LF |
| Host Header Poisoning | Unconstrained Host header value | RFC 9112 §3.2 | Requires header but no validation mandate | Whitelist expected Host values |
| Cache Poisoning | Unkeyed inputs reflected in response | RFC 9111 §4 | Cache key definition allows unsafe exclusions | Include security-relevant headers in cache key |
| Header Injection | Unvalidated header reflection | RFC 9110 §10 | No output encoding requirement | Context-appropriate output encoding |
| MITM (non-TLS) | Plaintext transmission allowed | RFC 9110 §17.2 | HTTP allows unencrypted traffic | Enforce HTTPS; use HSTS |
| Session Hijacking | Stateless design | RFC 9110 §3.3 | Protocol provides no session mechanism | Secure session tokens; HttpOnly/Secure flags |
| HTTP/2 Rapid Reset | Unlimited RST_STREAM rate | RFC 9113 §5.4 | No rate limiting requirement | Implement RST_STREAM rate limits |
| HPACK Bomb | Decompression ratio explosion | RFC 9113 §10.3, RFC 7541 | No maximum expansion ratio defined | Limit header list size; monitor expansion ratios |
| 0-RTT Replay | 0-RTT lacks replay protection | RFC 9114 §10.9 | Application must handle replay, not transport | Only allow idempotent requests in 0-RTT |
| HTTP/3 Connection Contamination | Connection reuse across origins | RFC 9114 §3.3 | Authority validation underspecified | Strict connection-to-origin binding |
| Web Cache Deception | Path normalization differentials | RFC 9110 §4.2, RFC 9111 | No normalization mandate | Consistent path normalization; no caching of dynamic content |
| Password Reset Poisoning | Host header trust | RFC 9112 §3.2 | No server validation requirement | Use configured base URL, not Host header |
| Credential Leakage | Authorization in logs/cache | RFC 9110 §11.6.2 | Limited logging guidance | Sanitize logs; never cache authenticated responses |
| DoS via Large Headers | No maximum header size | RFC 9110 §17.5 | "SHOULD enforce limits" not MUST | Enforce max header size (e.g., 8KB) |
| Virtual Host Confusion | Host-based routing trust | RFC 9112 §3.2 | No multi-tenant security guidance | Validate Host against expected values |
| Header Smuggling | Whitespace tolerance | RFC 9112 §5.1 | Some strictness but many tolerances | Zero tolerance for whitespace before colon |
| Client-Side Desync (CSD) | Server responds before reading full Content-Length | RFC 9112 §6.3 | No mandate to read full body before responding | Always read full Content-Length; close connections after partial reads |
| Pause-Based Desync | Chunk size and data in separate packets | RFC 9112 §7.1 | No timing requirements for chunk data arrival | Strict timing validation; buffer complete chunks |
| HTTP/2 Downgrade (H2.TE) | HTTP/2→HTTP/1.1 translation introduces CL/TE ambiguity | RFC 9113 §8, RFC 9112 §6.3 | No security guidance for protocol downgrading | End-to-end HTTP/2; strip CL/TE headers before downgrade |
| HTTP/2 Downgrade (H2.CL) | HTTP/2 frame length vs Content-Length mismatch | RFC 9113 §8, RFC 9112 §6.3 | Translation process creates smuggling vectors | Validate headers during downgrade; reject conflicts |
| H2C Smuggling | Upgrade: h2c header forwarded to back-end | RFC 9113 §3.4 | No security model for h2c in proxy chains | Strip Upgrade headers; disable h2c on back-end |
| HTTP Request Tunneling | Complete request in HTTP/2 body processed as second request | RFC 9113 §8.1 | Assumes one request per stream | Validate request bodies don't contain HTTP syntax |
| Response Queue Poisoning | Smuggled request causes persistent response misalignment | RFC 9112 §6 | No mechanism to detect/recover from queue poisoning | Prevent smuggling; limit requests per connection |
| HTTP Parameter Pollution | No standard for duplicate parameter handling | RFC 9110 §6.4.1, RFC 3986 §3.4 | No duplicate parameter parsing guidance | Canonicalize parameters; reject duplicates |
| Web Cache Deception (advanced) | Cache/origin normalization differentials | RFC 9110 §4.2, RFC 9111 §4 | No normalization standard; cache keys underspecified | Consistent normalization; include Content-Type in cache key |
| Transfer-Encoding Obfuscation | Lenient parsing accepts obfuscated TE headers | RFC 9112 §6.3, §2.2 | "Parse defensively" contradicts strict validation | Only accept exact "Transfer-Encoding: chunked" |
| HTTP Pipelining DoS | Rapid sequential requests without awaiting responses | RFC 9112 §9.3.2 | Optional feature with no rate limiting | Disable pipelining; limit requests per connection |

---

## Part VII: Security Verification Checklist

Use this checklist to assess HTTP security posture:

### Message Parsing Security
- [ ] Reject requests with both Content-Length and Transfer-Encoding headers
- [ ] Reject requests with whitespace between header name and colon
- [ ] Reject requests containing obs-fold (obsolete line folding)
- [ ] Reject requests with bare CR characters
- [ ] Enforce maximum request/response size limits
- [ ] Use strict (not lenient) parsing mode
- [ ] Validate all header values for CRLF injection
- [ ] Normalize Transfer-Encoding values (reject if not exactly "chunked")

### Header Validation
- [ ] Validate Host header against whitelist of expected values
- [ ] Never use Host header to construct URLs (use configured base URL)
- [ ] Sanitize all reflected headers with context-appropriate encoding
- [ ] Remove or sanitize X-Forwarded-* headers from untrusted sources
- [ ] Never log Authorization headers
- [ ] Set Cache-Control: no-store for authenticated responses
- [ ] Validate Referer header before trusting for security decisions

### Authentication & Authorization
- [ ] Enforce HTTPS for all authenticated requests (HSTS enabled)
- [ ] Use HttpOnly and Secure flags on all session cookies
- [ ] Implement anti-CSRF tokens
- [ ] Never include credentials in URLs
- [ ] Implement session timeout and re-authentication
- [ ] Use SameSite cookie attribute

### Caching Security
- [ ] Include security-relevant headers in cache keys
- [ ] Never cache authenticated responses
- [ ] Set Cache-Control: no-cache, no-store for sensitive content
- [ ] Validate that cached responses don't contain user-specific data
- [ ] Implement consistent path normalization between cache and origin

### HTTP/2 Specific
- [ ] Set conservative SETTINGS_MAX_CONCURRENT_STREAMS (e.g., 100)
- [ ] Implement rate limiting on RST_STREAM frames
- [ ] Limit CONTINUATION frame chain length
- [ ] Enforce SETTINGS_MAX_HEADER_LIST_SIZE
- [ ] Set timeout for incomplete header blocks
- [ ] Validate stream ID ordering

### HTTP/3 Specific
- [ ] Only allow idempotent methods in 0-RTT data
- [ ] Implement application-layer replay protection for sensitive operations
- [ ] Enforce strict connection-to-origin binding
- [ ] Validate certificate per-origin, not per-connection
- [ ] Never reuse connections across different security contexts

### Advanced Desync Attack Prevention
- [ ] Validate servers read full Content-Length before responding to POST requests
- [ ] Close connections after responding to potentially desynchronized requests
- [ ] Implement timeouts for partial body reads
- [ ] Validate Content-Length matches actual body size before processing
- [ ] Implement strict timing validation for chunked encoding
- [ ] Buffer and validate complete chunks before processing
- [ ] Reject chunked requests with suspicious timing patterns
- [ ] Monitor for pause-based desync attack patterns

### HTTP/2 Downgrade Security
- [ ] Use end-to-end HTTP/2 (avoid downgrading to HTTP/1.1)
- [ ] Strip Content-Length and Transfer-Encoding from HTTP/2 requests before downgrading
- [ ] Validate all headers in HTTP/2 requests before translation
- [ ] Implement secure downgrade translation that prevents smuggling
- [ ] Strip or hard-code Upgrade headers at edge (except WebSockets)
- [ ] Disable h2c (cleartext HTTP/2) on back-end servers
- [ ] Whitelist Upgrade targets (only WebSocket, reject h2c)
- [ ] Alert on h2c upgrade attempts in production

### Request Tunneling Prevention
- [ ] Validate request bodies don't contain HTTP syntax
- [ ] Ensure back-end only returns one response per HTTP/2 stream
- [ ] Alert if response body contains HTTP response patterns
- [ ] Validate Content-Type matches expected request format
- [ ] Implement strict stream-to-response mapping

### Response Queue Poisoning Prevention
- [ ] Use dedicated connections per user/session where possible
- [ ] Match response characteristics to expected request
- [ ] Limit requests per connection to minimize poisoning window
- [ ] Monitor for unexpected response patterns or timing anomalies
- [ ] Close connections after suspected smuggling attempts

### Parameter Pollution Defense
- [ ] Use consistent parameter parsing (first, last, or reject duplicates)
- [ ] Validate ALL occurrences of duplicate parameters
- [ ] Configure application to reject requests with duplicate parameters
- [ ] Use explicit array syntax for multiple values
- [ ] Ensure WAF and application parse parameters identically

### Web Cache Deception Prevention
- [ ] Implement consistent URL normalization between cache and origin
- [ ] Mark dynamic content with Cache-Control: no-store, private
- [ ] Use Vary header to include security-relevant headers in cache key
- [ ] Validate Content-Type matches file extension before caching
- [ ] Only cache explicitly approved static paths
- [ ] Alert on cached responses containing authentication cookies

### Transfer-Encoding Security
- [ ] Only accept exact "Transfer-Encoding: chunked" syntax
- [ ] Reject any Transfer-Encoding header variations or obfuscations
- [ ] Normalize headers: strip whitespace, lowercase field names
- [ ] Reject requests with duplicate Transfer-Encoding headers
- [ ] Test regularly with Burp Suite HTTP Request Smuggler extension

### HTTP Pipelining Controls
- [ ] Disable HTTP pipelining (should be default)
- [ ] Implement rate limiting per connection regardless of pipelining
- [ ] Set maximum requests per connection (e.g., 100)
- [ ] Monitor for rapid sequential requests without response waits
- [ ] Implement strict timeouts for pipelined request processing

### General Best Practices
- [ ] Deploy Web Application Firewall (WAF) with HTTP-specific rules
- [ ] Monitor for anomalous request patterns (rapid resets, smuggling attempts)
- [ ] Keep HTTP server/proxy software updated
- [ ] Disable unnecessary HTTP methods (e.g., TRACE, CONNECT if not needed)
- [ ] Implement rate limiting at multiple layers
- [ ] Use Content Security Policy (CSP) headers
- [ ] Set X-Content-Type-Options: nosniff
- [ ] Enable HTTPS Strict Transport Security (HSTS)
- [ ] Regularly test with automated smuggling detection tools
- [ ] Implement comprehensive logging and anomaly detection
- [ ] Conduct periodic security audits of HTTP processing logic

---

## Conclusion

HTTP's security challenges stem from fundamental architectural decisions made for flexibility, interoperability, and backward compatibility. This analysis of 27 vulnerability classes reveals systemic patterns:

### Core Security Principles

1. **Statelessness**: HTTP's stateless design delegates all security context to application layer, creating opportunities for session management vulnerabilities and enabling attacks like session fixation and token replay.

2. **Parsing Flexibility**: The "robustness principle" directly conflicts with security—lenient parsing enables differential interpretation attacks like request smuggling, with over 20 documented Transfer-Encoding obfuscation techniques exploiting this design choice.

3. **Trust Boundaries**: HTTP assumes hostile intermediaries in non-encrypted contexts but provides no protection mechanisms, mandating HTTPS for security. This architectural assumption makes MITM attacks trivial against unencrypted traffic.

4. **Version Evolution**: Each HTTP version introduces new attack surfaces while attempting to fix previous ones:
   - **HTTP/1.1**: Request smuggling via CL/TE conflicts, pipelining exploits
   - **HTTP/2**: Multiplexing DoS (Rapid Reset, MadeYouReset), downgrade attacks, h2c smuggling, HPACK bombs
   - **HTTP/3**: 0-RTT replay attacks, connection contamination, QUIC-specific vectors

5. **Specification Gaps**: Many security requirements use SHOULD instead of MUST, or provide multiple handling options, creating implementation inconsistencies that attackers exploit. Examples include parameter pollution (no duplicate handling standard), cache deception (no normalization mandate), and desync attacks (no timing requirements).

### Advanced Attack Evolution

Recent research (2023-2025) demonstrates attack sophistication:

- **Browser-Powered Desync**: Shifts attack execution from server-to-server to client-side, enabling XSS and cache poisoning via victim browsers
- **HTTP/2 Downgrade Exploitation**: Protocol translation creates three simultaneous length indicators, enabling H2.TE and H2.CL smuggling
- **Response Queue Poisoning**: Persistent connection state corruption causes catastrophic response misattribution across all users
- **Request Tunneling**: Hides complete requests inside HTTP/2 bodies, bypassing front-end security controls
- **Web Cache Deception**: Path normalization differentials enable sensitive data caching through delimiter confusion

### The Meta-Security Principle

Many HTTP vulnerabilities cannot be fixed at the protocol level without breaking compatibility. The specification authors made conscious trade-offs:
- Lenient parsing for interoperability vs. strict validation for security
- Multiple framing methods for flexibility vs. single canonical method for consistency
- Backward compatibility for adoption vs. deprecating dangerous features
- Statelessness for scalability vs. protocol-level session protection

**Defense requires defense-in-depth**: Strict parsing, comprehensive validation, encrypted transport, application-layer security controls, regular testing with tools like Burp Suite's HTTP Request Smuggler, monitoring for anomalous patterns, and staying current with evolving attack techniques documented in PortSwigger's annual Top 10 Web Hacking Techniques.

---

## Sources

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Top 10 CVEs of 2025: High-Impact Vulnerabilities & Exploitation Trends](https://socradar.io/blog/top-10-cves-of-2025-vulnerabilities-trends/)
- [Apache HTTP Server 2.4 vulnerabilities](https://httpd.apache.org/security/vulnerabilities_24.html)
- [PortSwigger: HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
- [Akamai: CVE-2025-32094 HTTP Request Smuggling](https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling)
- [Akamai: MadeYouReset HTTP/2 Protocol Attacks](https://www.akamai.com/blog/security/response-madeyoureset-http2-protocol-attacks)
- [OWASP: Testing for Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing-for-Host-Header-Injection)
- [OWASP: HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)
- [OWASP: Cache Poisoning](https://owasp.org/www-community/attacks/Cache_Poisoning)
- [PortSwigger: HTTP Host header attacks](https://portswigger.net/web-security/host-header)
- [PortSwigger: Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger: HTTP/3 connection contamination](https://portswigger.net/research/http-3-connection-contamination)
- [PortSwigger: Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [PortSwigger: Client-side desync attacks](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync)
- [PortSwigger: HTTP/2 downgrading](https://portswigger.net/web-security/request-smuggling/advanced/http2-downgrading)
- [PortSwigger: HTTP request tunnelling](https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling)
- [PortSwigger: Response queue poisoning](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning)
- [PortSwigger: Web cache deception](https://portswigger.net/web-security/web-cache-deception)
- [PortSwigger: Gotta cache 'em all](https://portswigger.net/research/gotta-cache-em-all)
- [PortSwigger: Pause-based desync attacks](https://portswigger.net/web-security/request-smuggling/browser/pause-based-desync)
- [PortSwigger: HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)
- [PortSwigger: Smashing the state machine](https://portswigger.net/research/smashing-the-state-machine)
- [PortSwigger: Top 10 web hacking techniques of 2024](https://portswigger.net/research/top-10-web-hacking-techniques-of-2024)
- [PortSwigger: Top 10 web hacking techniques of 2023](https://portswigger.net/research/top-10-web-hacking-techniques-of-2023)
- [PortSwigger: HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [OWASP: Testing for HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)
- [Imperva: HTTP Parameter Pollution](https://www.imperva.com/learn/application-security/http-parameter-pollution/)
- [HackTricks: Request Smuggling in HTTP/2 Downgrades](https://book.hacktricks.xyz/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades)
- [Imperva: Smuggling Requests with Chunked Extensions](https://www.imperva.com/blog/smuggling-requests-with-chunked-extensions-a-new-http-desync-trick/)
- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html)
- [RFC 9112: HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112.html)
- [RFC 9113: HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)
- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [RFC 9111: HTTP Caching](https://www.rfc-editor.org/rfc/rfc9111.html)
- [RFC 7541: HPACK Header Compression for HTTP/2](https://www.rfc-editor.org/rfc/rfc7541.html)
- [RFC 3986: Uniform Resource Identifier (URI): Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986.html)
