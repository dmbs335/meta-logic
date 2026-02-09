# OAuth 2.0/2.1 Security Specification Analysis

> **Analysis Target**: RFC 6749, RFC 6750, RFC 7636 (PKCE), RFC 9700 (Security BCP), OAuth 2.1 Draft
> **Methodology**: Specification-first analysis mapping attack vectors to RFC requirements
> **Latest Research**: August 2025 (USENIX Security '25, RFC 9700, Salesloft-Drift breach)
> **Date**: February 2026

---

## Executive Summary

OAuth 2.0's security challenges stem from **specification design choices that prioritize flexibility over safety**. RFC 6749 is *"relatively vague and flexible by design"* with *"vast majority of implementation optional"*, making it inherently vulnerable to misconfiguration. OAuth 2.1 addresses this by **mandating** previously optional security features and **removing** insecure grant types entirely. This analysis maps 17 vulnerability classes to specific RFC sections.

---

## Part I: Protocol Architecture Vulnerabilities

### 1. Bearer Token Architecture (RFC 6750)

RFC 6750 §1.2: *"Any party in possession of a bearer token can use it to get access to the associated resources (without demonstrating possession of a cryptographic key)."* Token theft = full impersonation — no cryptographic binding to the original client.

**Real case**: Salesloft-Drift Breach (August 2025) — stolen OAuth tokens from Drift's Salesforce integration accessed **700+ organizations** through token replay with no sender-constraining.

**Defense**: RFC 6750 §5.2 mandates TLS. RFC 9700 §4.10 recommends sender-constrained tokens (DPoP/mTLS). Token lifetime ≤1 hour (RFC 6750 §5.3).

### 2. Implicit Grant Flow (RFC 6749 §1.3.2, Removed in OAuth 2.1)

Tokens returned in URI fragments: `#access_token=ABC123`. Leakage via browser history, Referrer headers, JavaScript access, browser extensions. RFC 6749 §10.16 acknowledges: *"risks exposing it to the resource owner and other applications."*

**Evolution**: OAuth 2.1 completely removes implicit grant. RFC 9700 §2.1.2: *"Clients SHOULD use the authorization code grant instead."*

### 3. Authorization Code Interception → PKCE (RFC 7636)

Public clients cannot securely store secrets. Intercepted codes via malicious app URI schemes, deep link hijacking, or DNS rebinding can be exchanged for tokens. PKCE binds codes cryptographically: `code_challenge = SHA256(code_verifier)` → server validates verifier at token exchange.

**USENIX '25**: Even with PKCE, **11/18 integration platforms** vulnerable to Cross-app OAuth Account Takeover (COAT) due to lack of app differentiation. OAuth 2.1 mandates PKCE for all authorization code flows.

### 4. Redirect URI Validation (RFC 6749 §3.1.2)

Spec says servers *"compare and match"* but does NOT mandate **exact matching** — allowing substring, regex, wildcard, path traversal, and protocol downgrade bypasses.

**Evolution**: RFC 9700 §4.1.3: *"Authorization servers MUST utilize exact string matching of redirect URIs except for port numbers in localhost redirection URIs."* OAuth 2.1 mandates strict string matching.

### 5. State Parameter / CSRF (RFC 6749 §10.12)

State parameter is **SHOULD**, not MUST. Without it, attacker initiates OAuth flow → captures callback URL → victim visits attacker site → auto-submits → victim's session linked to attacker's OAuth account.

**Defense**: `state = HMAC(session_id, secret)`. Server-side comparison before code exchange. OAuth 2.1 strengthens emphasis but still not strictly mandatory.

---

## Part II: Token Lifecycle Vulnerabilities

### 6. Scope Upgrade (RFC 6749 §7)

Spec does NOT mandate server-side scope validation between authorization and token endpoints. Attacker authorized for `read:email` adds `admin` scope during token exchange → if server doesn't validate, elevated privileges granted. RFC 6749 §5.1 only requires *returning* granted scopes (informational), not validation.

**Defense**: Store authorized scope with code. Validate requested scope ⊆ authorized scope. Resource server must check scope per request.

### 7. Authorization Code Reuse (RFC 6749 §4.1.2)

Spec mandates: codes MUST expire in ~10 minutes, MUST NOT be used more than once. On reuse detection, server MUST deny and SHOULD revoke all derived tokens. Challenge: distributed systems need shared state for one-time-use tracking.

### 8. Refresh Token Security (RFC 6749 §10.4)

Refresh tokens are higher-value targets: long-lived (days-months), generate unlimited access tokens, no client auth for public clients. RFC 9700 §4.13: public clients MUST use refresh token rotation or sender-constrained tokens. OAuth 2.1 mandates one-time-use or sender-constrained refresh tokens.

**Real case**: CVE-2024-10318 (NGINX OpenID Connect) — session fixation via missing nonce validation enabled refresh token misuse.

### 9. Client Authentication (RFC 6749 §2.1)

Public clients (mobile/SPA) cannot have secrets — embedding `client_secret` in apps is extractable via reverse engineering. RFC 6749 §2.1: *"The authorization server MUST NOT rely on public client authentication for the purpose of identifying the client."*

**Defense**: Public clients use PKCE (no secrets). Confidential clients use HTTP Basic Auth, JWT assertions, or mTLS. Dynamic client registration (RFC 7591) for per-installation secrets.

### 10. Password Grant (RFC 6749 §1.3.3, Removed in OAuth 2.1)

Completely violates OAuth's core principle of separating client and resource owner credentials. Client sees plaintext password → logging, phishing, credential stuffing. RFC 9700 §2.4: *"MUST NOT be used."* OAuth 2.1: removed entirely.

---

## Part III: Advanced Attack Scenarios

### 11. Mix-Up Attack (RFC 9207)

Client supporting multiple authorization servers (AS1 honest, AS2 attacker-controlled) with same redirect_uri. Attacker intercepts and redirects to AS2 → victim authenticates → code sent to wrong AS. Defense: RFC 9207 adds `iss` parameter to responses. RFC 9700 §4.8: *"Clients MUST apply mix-up defense when interacting with multiple authorization servers."*

### 12. PKCE Downgrade Attack (RFC 9700 §4.7)

When PKCE is optional, attacker strips `code_challenge` parameters → server accepts non-PKCE flow → code injection possible. RFC 9700 §4.7.1: reject `code_verifier` if authorization had no `code_challenge`. OAuth 2.1: PKCE mandatory, eliminates downgrade.

### 13. COAT — Cross-App OAuth Account Takeover (USENIX '25)

Multi-app integration platforms where authorization codes aren't bound to specific `client_id`. Attacker intercepts code for App A, exchanges for App B → unauthorized access. **11/18 platforms vulnerable** including Microsoft, Google, Amazon. One CVE assigned CVSS 9.6.

**Defense**: Bind authorization codes to specific `client_id`. Validate code was issued for requesting client. Isolated OAuth configs per app.

### 14. Device Flow Phishing (RFC 8628)

Attacker initiates legitimate device flow → sends phishing email: *"Visit microsoft.com/devicelogin, enter code ABCD-1234"* → victim authenticates on legitimate Microsoft page → attacker receives token. **Bypasses MFA**. ShinyHunters campaign (2024-2025) targeted enterprises systematically.

**Defense**: Display device info on consent screen. Rate limit device code generation. Conditional Access policies restricting device flow.

### 15. Nonce Replay / Session Fixation (OpenID Connect)

CVE-2024-10318 (NGINX OIDC): Missing nonce validation → attacker injects ID token into victim's session → victim's actions attributed to attacker. OIDC Core §3.1.3.2 mandates nonce validation as MUST.

---

## Part IV: Token Protection Mechanisms

### 16. DPoP — Demonstrating Proof-of-Possession (RFC 9449)

Application-layer sender-constraining. Client generates key pair → all requests include DPoP JWT proof (method, URL, timestamp, signed with private key) → server binds token to public key → stolen token useless without private key. Supported by Auth0, Spring Security.

### 17. Mutual TLS (RFC 8705)

Transport-layer sender-constraining. Client presents certificate during TLS → server binds token to certificate thumbprint → validates on each request.

| Aspect | DPoP (RFC 9449) | mTLS (RFC 8705) |
|--------|-----------------|-----------------|
| Layer | Application (HTTP headers) | Transport (TLS) |
| CDN/Proxy | Works through proxies | Requires TLS passthrough |
| Browser | Works in browsers | Limited browser support |
| Use Case | SPAs, mobile apps | Server-to-server |

---

## Part V: CVE Summary

| CVE/Event | Component | Impact | Status |
|-----------|-----------|--------|--------|
| CVE-2024-10318 | NGINX OIDC | Session fixation, account takeover | Fixed Nov 2024 |
| CVE-2023-36019 | Azure AD/Entra ID | Privilege escalation, CVSS 9.6 | Patched 2023 |
| COAT/CORF | Integration Platforms (11/18) | Account takeover | CVSS 9.6 |
| Device Flow Campaign | Microsoft 365, Google | MFA bypass, enterprise compromise | Ongoing 2024-2025 |
| Salesloft-Drift | OAuth Token Storage | 700+ orgs compromised | August 2025 |

---

## Part VI: Attack-Spec-Defense Mapping

| Attack | Exploited Spec Behavior | Defense |
|--------|------------------------|---------|
| Code Interception | Public clients can't store secrets (§2.1) | PKCE with S256 (RFC 7636, OAuth 2.1 mandatory) |
| Redirect URI Manipulation | Non-exact matching allowed (§3.1.2) | Exact string matching (RFC 9700 §4.1.3) |
| Bearer Token Replay | Tokens usable by any possessor (RFC 6750) | DPoP (RFC 9449) or mTLS (RFC 8705) |
| Implicit Flow Leakage | Tokens in URL fragments (§1.3.2) | Remove implicit grant (OAuth 2.1) |
| OAuth CSRF | State is SHOULD, not MUST (§10.12) | Mandatory cryptographic state |
| Scope Upgrade | No validation mandate (§7) | Validate scope at token endpoint |
| Code Reuse | Code replayable without tracking | One-time use + revoke all on reuse |
| Refresh Token Theft | Long-lived, not sender-constrained (§10.4) | Rotation or DPoP binding (RFC 9700 §4.13) |
| Password Grant | Credential sharing by design (§1.3.3) | Prohibit entirely (RFC 9700, OAuth 2.1) |
| Mix-Up Attack | No issuer identification (gap) | `iss` parameter (RFC 9207) |
| PKCE Downgrade | PKCE optional (RFC 7636) | Reject verifier if no challenge (RFC 9700 §4.7.1) |
| COAT | No app differentiation (gap) | Bind codes to specific client_id |
| Device Code Phishing | Users can't verify device origin (RFC 8628) | Risk-based auth + user education |
| Nonce Replay | Nonce validation is SHOULD (OIDC) | Mandatory nonce validation + one-time use |

---

## Part VII: Security Checklist

**Authorization Server**: (1) TLS 1.2+ on all endpoints. (2) Exact redirect URI matching (RFC 9700 §4.1.3). (3) PKCE S256 support and enforcement. (4) One-time authorization codes, 10-min lifetime, revoke on reuse. (5) PKCE downgrade detection. (6) Scope validation at token endpoint. (7) Refresh token rotation for public clients. (8) DPoP/mTLS sender-constraining. (9) Issuer identification in responses (RFC 9207). (10) Remove implicit and password grants.

**Client Application**: (11) PKCE with 256-bit entropy code_verifier. (12) Cryptographic state parameter bound to session. (13) Validate state and issuer before code exchange. (14) HTTPS-only token requests. (15) Secure token storage (server-side session or encrypted keychain, NOT localStorage). (16) Handle refresh token rotation.

**Resource Server**: (17) Validate JWT signature/introspection. (18) Check exp, iss, aud, scope claims. (19) DPoP proof validation if applicable. (20) HTTPS-only, proper error codes.

---

## Part VIII: OAuth 2.0 → 2.1 Evolution

| Aspect | OAuth 2.0 (RFC 6749) | OAuth 2.1 |
|--------|----------------------|-----------|
| PKCE | Optional (RFC 7636) | **Mandatory** |
| Implicit Grant | Supported | **Removed** |
| Password Grant | Supported with warnings | **Removed** |
| Redirect URI | "Compare and match" | **Exact string matching** |
| Refresh Tokens | Confidential in transit | **Rotation/sender-constraining mandatory** |
| Issuer ID | Not specified | **Incorporated** (RFC 9207) |
| Bearer Alternative | Only bearer | **DPoP encouraged** (RFC 9449) |

---

## Sources

**Specs**: [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html) | [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) | [RFC 7636 (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636) | [RFC 9700 (Security BCP)](https://datatracker.ietf.org/doc/rfc9700/) | [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | [RFC 9449 (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449) | [RFC 8705 (mTLS)](https://www.rfc-editor.org/rfc/rfc8705.html) | [RFC 9207 (Issuer ID)](https://datatracker.ietf.org/doc/html/rfc9207) | [RFC 8628 (Device Flow)](https://datatracker.ietf.org/doc/html/rfc8628)

**Research**: [USENIX '25 COAT Paper](https://www.usenix.org/system/files/conference/usenixsecurity25/sec24winter-prepub-332-luo.pdf) | [Doyensec OAuth Vulns (2025)](https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html) | [PortSwigger OAuth](https://portswigger.net/web-security/oauth) | [Hackmanit Mix-Up](https://hackmanit.de/en/blog-en/132-how-to-protect-your-oauth-client-against-mix-up-attacks/) | [Device Flow Attacks](https://guptadeepak.com/oauth-device-flow-vulnerabilities-a-critical-analysis-of-the-2024-2025-attack-wave/) | [WorkOS OAuth BCP](https://workos.com/blog/oauth-best-practices) | [OWASP OAuth Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses)
