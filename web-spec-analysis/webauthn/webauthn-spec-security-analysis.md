# WebAuthn Security Analysis

> **Analysis Target**: W3C Web Authentication API Level 3, FIDO2 CTAP 2.1
> **Methodology**: Spec-first security analysis + CVE/attack research cross-mapping
> **Latest Cases**: CVE-2024-12225 (Quarkus), CVE-2024-9956 (Chrome Android), CVE-2025-24180, CVE-2025-26788 (StrongKey)
> **Date**: February 2026

---

## Executive Summary

WebAuthn's cryptographic foundations remain secure, but implementation-layer vulnerabilities, browser-level attacks, and passkey synchronization mechanisms create exploitable surfaces. Core attack surfaces: (1) **credential scope confusion** via rpID suffix matching, (2) **authentication downgrade** from phishing-resistant WebAuthn to phishable methods, (3) **synced passkey compromise** through cloud account takeover, (4) **API hijacking** via XSS/malicious extensions, (5) **implementation configuration errors** bypassing authentication entirely. 18 vulnerability classes mapped to spec sections.

---

## Part I: Protocol Architecture

### 1. Scoped Credential Model and Origin Binding (W3C §5.1.3, §13)

Credentials bound to Relying Party ID (rpID), which may be a registrable suffix of the origin. Suffix matching allows `site1.host.com` credentials to authenticate at `site2.host.com` — violates isolation in multi-tenant environments.

**CVE-2025-24180**: Malicious website claimed WebAuthn credentials from another website sharing a registrable suffix.

**Defense**: Exact domain matching where possible. Distinct rpIDs per subdomain. Server-side origin validation.

### 2. Challenge-Response and Replay Prevention (W3C §13)

Challenges must be unpredictable and fresh per ceremony. Weak randomness or predictable patterns allow precomputed responses or assertion reuse.

**CVE-2024-12225** (Quarkus, CVSS 9.1): Custom REST endpoints left default endpoints accessible → login cookie returned for existing usernames without proper challenge enforcement.

**Defense**: CSPRNG challenges, time-limited validity, reject reused/expired challenges.

### 3. User Verification vs. User Presence (W3C §5.4.4)

User Presence = physical interaction (touch). User Verification = biometric/PIN confirmation. `userVerification: "preferred"` or `"discouraged"` allows bypass of biometric/PIN → attacker only needs to touch authenticator.

**PoisonSeed campaign**: Abused cross-device authentication to trick users into approving login requests from fake portals with presence-only acceptance.

**Defense**: `userVerification: "required"` for high-security apps. Reject assertions without UV flag.

### 4. Attestation Types and Trust (W3C §6.5, §8, §13.4.4)

Five types: Basic (manufacturer cert), Self (own key), AttCA, Anonymization CA, None. Synced passkeys bypass attestation entirely — Apple/Google don't provide attestation for synced passkeys since the attested device may not be the one logging in.

**Defense**: Attestation validation per §7.1, trusted root allowlists, FIDO Metadata Service monitoring. Accept "None" only for low-security contexts.

### 5. Synced Passkey Compromise (W3C §6.1.3)

Backup Eligibility/State flags indicate credential synchronization. Multi-device credentials shift security model from device-bound to cloud-synchronized. Cloud account compromise (Google Password Manager, iCloud Keychain) exposes all synced passkeys.

**BlackHat 2025** (Chad Spensky): Demonstrated phishing cloud sync service → replicate passkeys. **DEF CON 33** (SquareX): Malicious extensions fake passkey registration/login → access enterprise SaaS without device or biometrics.

**Defense**: Inspect backup flags. Mandate device-bound credentials for AAL3 (NIST 800-63). Apply higher scrutiny to backup-eligible credentials.

---

## Part II: Authentication Ceremony Vulnerabilities

### 6. Cross-Origin Credential Claiming (W3C §13)

Related Origin Requests (experimental) allow credential sharing across related origins. Misconfiguration creates cross-site reuse. CVE-2025-24180 exploits insufficient origin validation across registrable suffixes.

**Defense**: Strict server-side origin validation. Reject mismatched `CollectedClientData.origin`. CSP to prevent script injection.

### 7. API Hijacking via Script Injection (W3C §13.4.8)

XSS or malicious extensions intercept `navigator.credentials.create()`/`.get()` → substitute attacker credentials, force password fallback, exfiltrate challenges.

**DEF CON 33** (SquareX): Forged both registration and login flows via WebAuthn API hijacking through JavaScript injection. **Journal of Computer Virology (2025)**: Browser-in-the-Middle + reflected XSS defeats FIDO2/WebAuthn.

**Defense**: Strict CSP, SRI for JavaScript resources, extension anomaly monitoring.

### 8. Authentication Downgrade (CTAP §5)

Applications with multiple auth methods (passkeys, push, SMS OTP) create downgrade surfaces. Attackers force victims from phishing-resistant WebAuthn to phishable methods.

**PoisonSeed**: Abused cross-device sign-in to trick users into approving from fake portals. **IOActive**: Weaponized Cloudflare Workers as transparent proxy to force fallback to phishable methods.

**Defense**: Disable fallback after WebAuthn registration. Alert on method changes. Rate limiting.

### 9. Cross-Device Session Hijacking (W3C §14.5)

QR code/deep link authentication for cross-device flows → attacker presents QR on fake login page → user scans with legitimate device → approval bound to attacker's session.

**Defense**: Display session context during cross-device auth. Session binding with device/IP metadata. Explicit confirmation showing target service.

---

## Part III: Authenticator & CTAP Security

### 10. PIN/UV Protocol Security (CTAP §6.5)

PIN brute-force or protocol weaknesses bypass user verification.

**CVE-2024-9956** (Chrome Android): Local attackers within Bluetooth range escalated privileges via crafted HTML pages.

**Defense**: Minimum 8-char PIN, retry limits with exponential backoff, pinUvAuthToken expiration, encrypted BLE transport.

### 11. Signature Counter Limitations (W3C §6.1, §13.4.6)

Counter-based clone detection provides limited protection: stateless authenticators can't maintain counters, synced passkeys don't implement counters, most implementations accept counter 0 without validation. Global counters enable cross-site correlation (privacy risk).

**Defense**: Treat counter anomalies as warning signals (not hard failures). Combine with fraud detection.

### 12. Transport Security (CTAP §8, §13.2)

USB HID: channel locking. NFC: proximity-based. BLE: link encryption mandatory. CVE-2024-9956 demonstrated BLE proximity assumption violation.

---

## Part IV: Implementation Vulnerabilities

### 13. Default Endpoint Bypass (CVE-2024-12225)

Quarkus WebAuthn module (CVSS 9.1): custom REST endpoints left default endpoints accessible → anyone could log in as existing user by knowing username.

### 14. Credential Type Confusion (CVE-2025-26788)

StrongKey FIDO Server: failed to distinguish discoverable vs non-discoverable credential flows → attacker starts flow with victim's username, signs challenge with own passkey → gains access to victim's account.

**Defense**: Strict credential ownership validation. Verify credential ID matches stored credential for that user.

### 15. Extension Processing (W3C §9, §13)

Spec allows optional extensions that could bypass security checks or leak information. SquareX API hijacking demonstrates how malicious extensions manipulate authentication flows.

**Defense**: Server-side extension allowlist. Reject unknown extensions. Client integrity checks.

---

## Part V: Privacy Concerns

### 16. Credential ID Privacy (W3C §14.6.3)

Credential enumeration reveals whether user has credentials at a service. Timing attacks on credential lookup enable cross-site user tracking (arXiv:2205.08071).

**Defense**: CSPRNG credential IDs, constant-time operations, consistent error responses, rate limiting.

### 17. Biometric Data Privacy (W3C §14)

Spec mandates authenticator-local biometric processing — templates never leave device. Security depends on authenticator implementation quality.

---

## CVE Summary (2024-2025)

| CVE | CVSS | Component | Root Cause |
|-----|------|-----------|------------|
| CVE-2024-12225 | 9.1 | Quarkus WebAuthn | Default endpoints accessible alongside custom ones |
| CVE-2024-9956 | High | Chrome Android | BLE transport privilege escalation |
| CVE-2025-24180 | TBD | Cross-site | rpID suffix matching → credential claiming |
| CVE-2025-26788 | Critical | StrongKey FIDO | Credential type confusion → auth bypass |

---

## Attack-Spec-Defense Mapping

| Attack | Spec Reference | Defense |
|--------|---------------|---------|
| Cross-site credential reuse | §5.1.3 (rpID suffix matching) | Exact domain matching, strict origin validation |
| Replay attack | §13 (challenge-response) | CSPRNG challenges, time-limited validity |
| Presence-only bypass | §5.4.4 (UV optional) | `userVerification: "required"`, validate UV flag |
| Attestation bypass | §6.5, §8 (None allowed) | Require attestation for high-security contexts |
| Synced credential compromise | §6.1.3 (backup eligible) | Inspect backup flags, device-bound for AAL3 |
| API hijacking | §13.4.8 (client-side JS) | Strict CSP, SRI, extension monitoring |
| Auth downgrade | §5.4.4 (multiple methods) | Disable fallback after WebAuthn registration |
| Cross-device session hijack | §14.5 (cross-device auth) | Session binding, display context, validate device |
| PIN brute force | CTAP §6.5 | Retry limits, exponential backoff, token expiration |
| Clone detection bypass | §6.1, §13.4.6 (counter optional) | Combine with fraud detection |
| Default endpoint exploit | §5, §7 (implementation) | Disable defaults, security reviews |
| Credential type confusion | §6.1 (discoverable vs non-discoverable) | Validate credential ownership, type-specific flows |
| Credential enumeration | §14.6.3 (ID lookup) | Constant-time ops, consistent responses |
| Timing correlation | §14 (lookup timing) | Per-credential counters, constant-time implementation |

---

## Sources

**Specs**: [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) | [FIDO2 CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html)

**CVEs**: [CVE-2024-12225 (Quarkus)](https://www.ameeba.com/blog/cve-2024-12225-critical-security-vulnerability-in-quarkus-webauthn-module/) | [CVE-2024-9956 (Chrome)](https://www.offsec.com/blog/cve-2024-9956/) | [CVE-2025-24180](https://www.wiz.io/vulnerability-database/cve/cve-2025-24180) | [CVE-2025-26788 (StrongKey)](https://www.securing.pl/en/cve-2025-26788-passkey-authentication-bypass-in-strongkey-fido-server/)

**Research**: [BlackHat/DEF CON 2025 WebAuthn](https://idpro.org/blackhat-and-def-con-2025-thoughts/) | [SquareX Passkeys Pwned](https://labs.sqrx.com/passkeys-pwned-turning-webauth-against-itself-0dbddb7ade1a) | [IOActive Auth Downgrade](https://www.ioactive.com/authentication-downgrade-attacks-deep-dive-into-mfa-bypass/) | [arXiv FIDO2 Timing](https://arxiv.org/abs/2205.08071) | [OWASP Auth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
