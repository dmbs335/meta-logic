# SAML Spec Security Analysis

> **Analysis Target**: SAML 2.0 (OASIS Standard), RFC 7522 (SAML Profile for OAuth 2.0), OASIS Security and Privacy Considerations
> **Methodology**: Spec analysis + CVE/attack research cross-mapping
> **Latest Cases**: CVE-2025-47949 (samlify), CVE-2025-25291/25292 (ruby-saml), CVE-2024-45409 (CVSS 10.0), Golden/Silver SAML
> **Date**: February 2026

---

## Executive Summary

SAML's XML-based architecture creates inherent complexity risks. Core attack surfaces: (1) **XML Signature Wrapping (XSW)** exploiting two-phase processing (validate then parse) with parser differentials, (2) **Golden/Silver SAML** forging tokens with stolen signing keys, (3) **assertion validation gaps** (audience, timestamp, replay, SubjectConfirmation), (4) **XML processing attacks** (XXE, injection, DoS), (5) **parser differentials** between signature validators and assertion processors. 22 vulnerability classes mapped. Ruby-saml alone had 3 critical CVEs in January 2025.

---

## Part I: Protocol Architecture

### 1. XML-Based Trust Model (OASIS SAML 2.0 Core)

XML processing stack introduces parser differentials — signature validator and assertion processor may have "different views" on the same document. XML Signature Wrapping (XSW) modifies message structure by injecting forged elements without invalidating signatures.

**CVEs**: CVE-2025-47949 (samlify — complete auth bypass via XSW), CVE-2024-45409 (ruby-saml, CVSS 10.0 — forged SAML responses), CVE-2025-25291/25292 (ruby-saml — login as any user with single valid signature).

**Defense**: OASIS recommends absolute XPath expressions, schema validation before security processing, never `getElementsByTagName` for security elements.

### 2. Bearer Token Model (RFC 7522 §3)

SAML assertions are bearer tokens — presenting valid assertion proves identity without additional verification. RFC 7522: *"The specification does not mandate replay protection."* Stolen assertions valid until expiration.

**Golden SAML** (CyberArk 2017): Steal federation server's private signing key → forge tokens for any user with any privileges. Used in SolarWinds/Solorigate. **Silver SAML** (Semperis 2024): Extended to cloud (Entra ID) — obtain externally generated certificate's private key → forge any SAML response without ADFS access.

**Defense**: Assertions ≤60s validity. Maintain used ID cache for replay prevention (RFC 7522 §5). HSM key storage. Certificate pinning.

### 3. Stateless Design — No Real-Time Revocation (SAML 2.0 Profiles)

Self-contained signed assertions can't be revoked before expiration. Single Logout (SLO) is fragile — requires all SPs to support it, network disruptions break the chain, partial logout leaves exploitable sessions.

**Defense**: Short validity windows. Don't rely solely on SLO for security. Re-authentication for sensitive operations.

---

## Part II: Signature Verification Vulnerabilities

### 4. XML Signature Wrapping — XSW (OASIS Security Considerations)

8 distinct XSW variants exploit different XML structure manipulations. Original signed assertion moved to wrapper node while malicious assertion added. Attribute pollution (duplicate attributes), namespace confusion between validators and processors.

**Real-world**: TOPdesk (impersonate any user), SimpleSAMLphp/xmlseclibs bypass (Hackmanit), PortSwigger "The Fragile Lock" (Black Hat Europe).

**Defense**: Absolute XPath, schema validation, unified parser for signature and assertion processing.

### 5. XML Canonicalization Comment Injection (CVE-2017-11428)

xml-exc-c14n strips comments before signature verification, but comments present when application parses identifiers. `<NameID>victim@org.com<!--COMMENT-->.evil.com</NameID>` — signature validates full string, app sees `victim@org.com`.

**Defense**: Remove all XML comments before processing assertions.

### 6. Algorithm Substitution / "None" Algorithm (XMLDSig)

`<SignatureMethod>` element specifies algorithm → confused deputy. Attacker downgrades to weak algorithms (RSA-SHA1, RSA-MD5) or specifies "none". Key confusion: switching RSA to HMAC where attacker controls the key.

**BlackHat 2019** (Alvaro Munoz): SAML auth bypass via "dupe key confusion" — sign token with arbitrary symmetric key.

**Defense**: RFC 7522 mandates digital signature or MAC. Use StaticKeySelector with pre-configured keys, never trust KeyInfo elements.

### 7. KeyInfo Trust / Certificate Validation (XMLDSig §4.4)

`<KeyInfo>` can contain verification key/certificate. Blindly trusting embedded certificates → attacker includes own cert, creates valid signatures. Metadata poisoning convinces SPs to trust wrong certificates.

**Defense**: Pre-existing trust (PKI). StaticKeySelector from IdP directly. Ignore KeyInfo in assertions.

---

## Part III: Assertion Validation Vulnerabilities

### 8. Audience Restriction Bypass (RFC 7522 §3, SAML Core §2.5.1.4)

Without audience validation, assertions intercepted from one SP can be replayed at another SP using same IdP. RFC 7522: *"MUST reject any Assertion that does not contain its own identity as the intended audience."*

### 9. Bearer Method Exploitation (SAML Core §2.4.1.1)

No proof-of-possession — anyone possessing the token can use it. Token theft via compromised proxies, XSS, malware. Office 365 SAML token exploitation (BlackHat): click "keep me signed in" → mount concealed drive → exfiltrate data bypassing AV/DLP.

**Defense**: Maintain used ID cache (replay prevention), minimal validity periods, single-use assertions.

### 10. Timestamp Validation Failures (RFC 7522 §3)

Excessive clock skew (>5 min) extends replay window. Some implementations skip NotOnOrAfter validation entirely.

**Defense**: 1-minute assertion lifetime, ≤30s clock skew.

### 11. InResponseTo / Replay Protection (SAML Profiles §4.1.4.2)

SP-initiated: InResponseTo must match sent request ID. IdP-initiated flows inherently more vulnerable (no request to correlate). Unsolicited responses must NOT contain InResponseTo value.

**Defense**: InResponseTo + assertion ID tracking + short validity.

### 12. SubjectConfirmation Validation (Sustainsys GHSA-9475-xg6m-j7pw)

Library failed to enforce bearer method requirements — using holder-of-key assertions without possessing the key.

**Defense**: Strictly validate SubjectConfirmation method and SubjectConfirmationData (Recipient, NotOnOrAfter, InResponseTo).

---

## Part IV: XML Processing Attacks

### 13. XXE Injection (OWASP SAML Security)

SAML responses are XML → external entity processing enables file disclosure, SSRF, Billion Laughs DoS.

**CVEs**: CVE-2016-10149 (pysaml2), CVE-2017-1000452 (samlify), CVE-2024-52806 (simplesamlphp/saml2).

**Defense**: Disable external entities (`disallow-doctype-decl = true`). Never auto-download schemas from third-party locations.

### 14. XML Injection (NCC Group 2021)

User input concatenated into SAML messages → attribute injection, NameID manipulation, assertion injection.

**Defense**: Never construct SAML via string concatenation. Use secure XML generation libraries.

### 15. DoS via XML Processing (OASIS Security Considerations)

OASIS warns: *"Handling a SAML request is potentially a very expensive operation."* Deeply nested XML, large documents, entity expansion, compressed response DoS.

**CVE-2025-25293** (ruby-saml, CVSS 7.7): DoS via compressed SAML responses.

**Defense**: Resource limits (max size, depth, entity expansion). Rate limiting.

---

## Part V: Encryption & Implementation Issues

### 16. Weak/Missing Assertion Encryption (SAML Core §6)

Encryption is optional. Base64 encoding ≠ encryption — assertions readable at TLS termination points, in logs, via MitM. XML Encryption itself has CBC padding oracle vulnerabilities.

**Defense**: Assertion encryption for sensitive attributes. If XMLEnc used, authenticated encryption (GCM mode). Prefer TLS 1.3+.

### 17. Parser Differentials (GitHub Security 2024-2025)

Multiple XML parsers in the SAML stack with different handling of attribute duplication, namespace resolution, character encoding, whitespace.

**GitHub Blog (2024)**: "Sign in as anyone" — parser differentials bypassed XML Signature validation. **CVE-2025-25291/25292**: Single valid signature → construct SAML assertions → login as any user (affected GitLab).

**Defense**: Consistent XML processing stack. Strict schema validation. Absolute XPath. PortSwigger parser differential testing toolkit.

### 18. RelayState Injection (SAML Bindings §3.4.3)

Unvalidated RelayState URLs → open redirect (phishing after legitimate auth) or SSRF.

**Defense**: URL allowlist for RelayState values.

### 19. Certificate/Key Management (OASIS §4.3)

Reusing keys across signing/encryption. Key rotation gaps causing emergency bypasses. Golden/Silver SAML from stolen signing keys.

**Defense**: Separate signing/encryption certificates (OWASP). HSM storage. Key rotation with overlap periods. Monitor certificate usage.

---

## CVE Summary (2024-2025)

| CVE | Component | CVSS | Attack |
|-----|-----------|------|--------|
| CVE-2024-45409 | ruby-saml | 10.0 | Forged SAML responses → arbitrary user login |
| CVE-2025-47949 | samlify | Critical | XSW → complete auth bypass |
| CVE-2025-25291/25292 | ruby-saml | Critical | Parser differential → login as any user |
| CVE-2025-25293 | ruby-saml | 7.7 | Compressed response DoS |
| CVE-2024-4985/9487 | GitHub Enterprise | Critical | SAML bypass via encrypted assertions |
| CVE-2024-8698 | Keycloak | High | SAML processing auth bypass |

---

## Attack-Spec-Defense Mapping

| Attack | Spec Reference | Defense |
|--------|---------------|---------|
| XML Signature Wrapping | OASIS Sec Considerations | Absolute XPath, schema validation, unified parser |
| Comment Injection | xml-exc-c14n algorithm | Remove all comments before processing |
| XXE Injection | XML 1.0 Spec | Disable external entities and DTDs |
| Replay Attacks | RFC 7522 §5 | InResponseTo validation, ID tracking, short lifetime |
| Audience Bypass | RFC 7522 §3 | Strict audience MUST validation |
| Golden/Silver SAML | SAML trust model | HSM key storage, certificate pinning, anomaly detection |
| Algorithm Substitution | XMLDSig spec | StaticKeySelector, algorithm allowlist |
| RelayState Injection | SAML Bindings §3.4.3 | URL allowlist |
| Timestamp Bypass | RFC 7522 §3 | Strict NotBefore/NotOnOrAfter, minimal skew |
| SLO Failures | SAML Profiles §4.4 | Short sessions, don't rely solely on SLO |
| Parser Differentials | Implementation gap | Unified parsing stack, strict validation |
| Metadata Poisoning | SAML Metadata | Signed metadata, secure distribution |
| Encryption Weaknesses | SAML Core §6, XMLEnc | Mandatory encryption, avoid CBC, TLS 1.3+ |

---

## Sources

**Specs**: [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) | [OASIS Security Considerations](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf) | [RFC 7522](https://datatracker.ietf.org/doc/html/rfc7522)

**Research**: [GitHub "Sign in as anyone"](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/) | [PortSwigger "The Fragile Lock"](https://portswigger.net/research/the-fragile-lock) | [USENIX 2012 "On Breaking SAML"](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf) | [CyberArk Golden SAML](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps) | [Semperis Silver SAML](https://www.semperis.com/blog/meet-silver-saml/) | [OWASP SAML Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)

**CVEs**: [CVE-2024-45409 (ruby-saml)](https://thehackernews.com/2025/03/github-uncovers-new-ruby-saml.html) | [CVE-2025-47949 (samlify)](https://www.endorlabs.com/learn/cve-2025-47949-reveals-flaw-in-samlify-that-opens-door-to-saml-single-sign-on-bypass) | [CVE-2024-4985 (GitHub Enterprise)](https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass)
