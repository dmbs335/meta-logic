# SAML Spec Security Analysis: Direct Extraction from RFC and OASIS Standards

> **Analysis Target**: SAML 2.0 (OASIS Standard), RFC 7522 (SAML Profile for OAuth 2.0), OASIS Security and Privacy Considerations
> **Methodology**: Threat landscape research → Specification analysis → Attack vector mapping → Defense extraction
> **Latest Cases Reflected**: CVE-2025-47949, CVE-2025-25291/25292, CVE-2024-45409, Ruby-SAML vulnerabilities (2024-2025)

---

## Part 1: Protocol Architecture and Fundamental Security Design

### 1. XML-Based Trust Model Creates Inherent Complexity Risks (OASIS SAML 2.0 Core)

**Spec Design Decision**: SAML uses XML as the message format with XML Digital Signature (XMLDSig) for integrity and XML Encryption (XMLEnc) for confidentiality. This design choice prioritizes interoperability and extensibility over simplicity.

**Security Implications**: The XML processing stack introduces multiple layers where implementation differences can create security vulnerabilities. XML parsers, canonicalization algorithms, and signature validators may have divergent interpretations of the same document, creating "parser differential" attack surfaces.

**Attack Vectors**:
- **XML Signature Wrapping (XSW)**: Attackers modify the message structure by injecting forged elements without invalidating the signature. The signature validator and assertion processor may have "different views" on the document.
- **Parser Differentials**: GitHub Security researchers discovered that "multiple hacking techniques allowed potential attackers to completely bypass XML signature validation while still presenting a valid SAML document to an application."
- **Canonicalization Attacks**: XML canonicalization algorithms (xml-exc-c14n) strip comments before signature verification, but if comments are processed differently by assertion evaluators, attackers can inject malicious data.

**Real-World Cases**:
- **CVE-2025-47949** (samlify): Signature Wrapping attack allowing complete authentication bypass and arbitrary user impersonation
- **CVE-2024-45409** (ruby-saml, CVSS 10.0): Critical vulnerability allowing attackers to log in as arbitrary users by forging SAML responses
- **On Breaking SAML: Be Whoever You Want to Be** (USENIX Security 2012): First comprehensive analysis of XSW attacks

**Spec-Based Defense**: OASIS Security Considerations document recommends: *"Always perform schema validation on the XML document prior to using it for any security-related purposes"* and *"Always use absolute XPath expressions to select elements, unless a hardened schema is used for validation."*

---

### 2. Bearer Token Model Without Built-In Revocation (RFC 7522 §3)

**Spec Design Decision**: RFC 7522 explicitly states that *"The specification does not mandate replay protection for the SAML Assertion usage for either the authorization grant or for client authentication. It is an optional feature, which implementations may employ at their own discretion."*

**Security Implications**: SAML assertions are bearer tokens—presenting a valid assertion proves the bearer's identity without additional verification. Combined with the lack of mandatory revocation mechanisms, stolen assertions remain valid until expiration.

**Attack Vectors**:
- **Token Theft and Replay**: An attacker intercepting a SAML assertion can use it to authenticate as the victim within the validity window.
- **Golden SAML Attack**: CyberArk (2017) discovered that attackers gaining control of the federation server's private signing key can forge SAML tokens for any user with any privileges, across all integrated applications.
- **Silver SAML Attack** (2024): Semperis researchers extended Golden SAML to cloud environments (Entra ID). Attackers who obtain the private key of an externally generated certificate can "forge any SAML response they want" without accessing ADFS.

**Real-World Cases**:
- **SolarWinds/Solorigate**: Attackers used Golden SAML to maintain persistent access to victim organizations
- Silver SAML rated as MODERATE to SEVERE risk depending on compromised system

**Spec-Based Defense**: RFC 7522 §5 requires: *"The Assertion MUST have an expiry that limits the time window during which it can be used."* Best practice: assertions should have validity periods of 1 minute or less. Additionally, *"In the case of the 'bearer' method, the Relying Party MUST ensure that assertions are not replayed, by maintaining the set of used ID values for the length of time for which the assertion would be considered valid."*

---

### 3. Stateless Design Prevents Real-Time Session Invalidation (SAML 2.0 Profiles)

**Spec Design Decision**: SAML assertions are self-contained, signed documents. Service Providers validate assertions independently without real-time consultation with the Identity Provider.

**Security Implications**: Once issued, assertions cannot be revoked before expiration. This creates a window of vulnerability when credentials are compromised or access should be immediately terminated.

**Attack Vectors**:
- **Post-Compromise Access**: After an account compromise is detected and credentials are reset at the IdP, existing SAML assertions remain valid.
- **Single Logout (SLO) Fragility**: SAML SLO "has some significant restrictions and drawbacks, which make it fragile and challenging to implement." For SLO to work, "both the IdP and all SPs must be configured to support SLO; otherwise, various sessions may not be terminated."

**Real-World Cases**:
- Organizations often discover that SLO only partially succeeds, leaving "unattended sessions to be exploited"
- Network disruptions, server overloads, or firewall configurations can block logout requests, breaking the SLO chain

**Spec-Based Defense**: OASIS Security Considerations recommends short validity windows and transport-layer security. *"Where message integrity and message confidentiality are required, then HTTP over SSL 3.0 or TLS 1.0 is recommended."* (Note: Modern implementations should use TLS 1.2+)

---

## Part 2: Signature Verification Vulnerabilities

### 4. XML Signature Wrapping Attacks (OASIS Security Considerations)

**Spec Fundamental Issue**: XML documents with signatures are processed in two independent steps: (1) signature validation and (2) assertion evaluation. If these modules have "different views" on the document structure, attacks become possible.

**Security Implications**: *"The attacker modifies the message structure by injecting forged elements, which do not invalidate the signature."* The original signed assertion is moved to a wrapper node while a new malicious assertion is added.

**Attack Vectors**:
- **XSW Variant 1-8**: Academic research identified 8 distinct XSW attack variants exploiting different XML structure manipulations
- **Attribute Pollution**: Injecting duplicate attributes with different values where validators use the first value but processors use the last
- **Namespace Confusion**: Exploiting namespace handling differences between signature validators and assertion processors

**Real-World Cases**:
- **TOPdesk** vulnerable to XSW allowing attackers with credentials to "impersonate any user"
- **SimpleSAMLphp and xmlseclibs** signature validation bypass (Hackmanit research)
- PortSwigger's "The Fragile Lock" (Black Hat Europe) demonstrated novel XSW techniques bypassing modern defenses

**Spec-Based Defense**: OASIS Security Considerations: *"Never use getElementsByTagName to select security related elements in an XML document without prior validation. Always use absolute XPath expressions to select elements."* Additional guidance: *"Even signing the whole document does not necessarily protect against XSW attacks."*

---

### 5. XML Canonicalization Comment Injection (CVE-2017-11428 Family)

**Spec Behavior**: XML canonicalization algorithm (xml-exc-c14n) strips XML comments during transformation prior to signature verification. However, *"comment nodes should have no effect—and due to canonicalization of XML prior to signature verification, inserting an XML comment into a SAML message does not invalidate its signature."*

**Security Implications**: Comments are removed before signature verification but may be present when application code parses user identifiers or attributes, allowing attackers to inject data that bypasses authentication.

**Attack Vectors**:
- **Username Splitting**: Injecting `<NameID>victim@org.com<!--COMMENT-->.evil.com</NameID>` where signature validates the full string, but application splits at the comment, seeing only `victim@org.com`
- **Attribute Value Manipulation**: Similar injection in attribute values to escalate privileges or modify authorization decisions

**Real-World Cases**:
- Duo Security (DUO-PSA-2017-003): Comment injection vulnerability in SAML authentication
- Multiple SAML libraries affected by CVE-2017-11428 family of vulnerabilities

**Spec-Based Defense**: Implementation guidance recommends: *"SAML library authors should look for an option in their XML library to remove all comments when creating and parsing XML documents, as strategically purging all XML comments upfront avoids this issue entirely."*

---

### 6. Algorithm Substitution and "None" Algorithm Attacks (XML-Signature Spec)

**Spec Flexibility**: XML Signature allows the signed document to specify its own signature algorithm via the `<SignatureMethod>` element. This creates a confused deputy scenario.

**Security Implications**: If validators don't strictly enforce expected algorithms, attackers can downgrade to weaker algorithms or specify "none" to bypass signature verification entirely.

**Attack Vectors**:
- **Algorithm Downgrade**: Substituting strong algorithms (RSA-SHA256) with weak or broken ones (RSA-SHA1, RSA-MD5)
- **"None" Algorithm**: Some implementations accepted unsigned assertions when algorithm was set to "none"
- **Key Confusion**: Switching from asymmetric (RSA) to symmetric (HMAC) algorithms where the attacker controls the key

**Real-World Cases**:
- Microsoft SAML authentication bypass via "dupe key confusion" (Black Hat 2019): Alvaro Munoz demonstrated how attackers could "sign a SAML authentication token with an arbitrary symmetric key"
- Multiple JWT libraries had similar "alg: none" vulnerabilities, pattern repeated in SAML

**Spec-Based Defense**: RFC 7522 mandates: *"The Assertion MUST be digitally signed or have a Message Authentication Code (MAC) applied by the issuer. The authorization server MUST reject Assertions with an invalid signature or MAC."* Implementations should use StaticKeySelector with pre-configured keys rather than trusting KeyInfo elements.

---

### 7. KeyInfo Trust and Certificate Validation Weaknesses (XML-Signature §4.4)

**Spec Design**: XML Signature includes a `<KeyInfo>` element that can contain the public key or certificate used for verification. The spec allows multiple formats (X509Data, KeyValue, etc.).

**Security Implications**: If service providers blindly trust certificates embedded in SAML assertions, attackers can include their own certificates and create valid signatures with their own keys.

**Attack Vectors**:
- **Self-Signed Certificate Injection**: Including attacker-controlled certificates in KeyInfo
- **Certificate Substitution**: Replacing legitimate certificates with malicious ones
- **Metadata Manipulation**: Convincing SPs to trust wrong certificates through metadata poisoning

**Real-World Cases**:
- OASIS guidance warns: *"If metadata URLs are not used, great care must be taken to assure that an attacker does not convince an SP to trust the wrong certificate"*

**Spec-Based Defense**: OASIS Security Considerations: *"The primary mechanism is for the relying party and asserting party to have a pre-existing trust relationship which typically relies on a Public Key Infrastructure (PKI). While use of a PKI is not mandated by SAML, it is recommended."* Best practice: *"If you expect only one signing key, use StaticKeySelector and obtain the key directly from the identity provider, store it in a local file and ignore any KeyInfo elements in the document."*

---

## Part 3: Assertion Validation and Processing Vulnerabilities

### 8. Audience Restriction Bypass (RFC 7522 §3, SAML Core §2.5.1.4)

**Spec Requirement**: RFC 7522 mandates: *"The assertion MUST contain a `<Conditions>` element with an `<AudienceRestriction>` element with an `<Audience>` element that identifies the authorization server as an intended audience. The authorization server MUST reject any Assertion that does not contain its own identity as the intended audience."*

**Security Implications**: The Audience restriction prevents token reuse across different service providers. Without proper validation, an attacker can intercept assertions intended for one SP and replay them at another SP using the same IdP.

**Attack Vectors**:
- **Cross-Service Token Replay**: Authenticate to legitimate SP, intercept SAML response, replay to target SP
- **Token Recipient Confusion**: "Some Service Providers don't bother to check if they're the intended recipient, relying only on the validity of assertion signatures"

**Real-World Cases**:
- WorkOS research documented SPs that skip recipient validation: "valid signatures aren't enough to prevent unwanted access"
- Attack requires: (1) legitimate account on any SP, (2) target SP accepts tokens from same IdP

**Spec-Based Defense**: RFC 7522 strict validation: *"The authorization server MUST reject any Assertion that does not contain its own identity as the intended audience."* Additionally validate: *"The response destination is present, non-empty, and refers to an ACS URL that you are expecting; and the response and assertion issuers refer to an IdP EntityID you recognize."*

---

### 9. SubjectConfirmation Bearer Method Vulnerabilities (SAML Core §2.4.1.1)

**Spec Design**: SAML bearer confirmation method assumes: *"SAML tokens are usually used as bearer tokens—a caller that presents a token is assumed to be the subject of the token."*

**Security Implications**: Bearer tokens have no proof-of-possession mechanism. Anyone possessing the token can use it within its validity period.

**Attack Vectors**:
- **Token Theft via MITM**: Even with TLS, tokens can be stolen through compromised proxies, browser extensions, or malware
- **XSS-Based Token Exfiltration**: Cross-site scripting can extract tokens from browser memory or HTTP headers
- **Insider Threats**: "Without conditions on use, an attacker that successfully steals such an assertion has many more targets of opportunity"

**Real-World Cases**:
- Office 365 SAML token exploitation (Black Hat research): "An attacker could get the SAML token by clicking 'keep me signed in' when signing into Office 365, mount and conceal a new drive, and take data while bypassing antivirus, DLP, and sandboxes"

**Spec-Based Defense**: SAML Core specification requires for bearer method: *"The Relying Party MUST ensure that assertions are not replayed, by maintaining the set of used ID values for the length of time for which the assertion would be considered valid based on the NotOnOrAfter attribute."* Additionally, assertions should have minimal validity periods and be single-use.

---

### 10. Timestamp Validation Failures (RFC 7522 §3, SAML Core §2.5.1)

**Spec Requirement**: RFC 7522 mandates: *"The authorization server MUST reject the entire Assertion if the NotOnOrAfter instant on the `<Conditions>` element has passed (subject to allowable clock skew between systems)."*

**Security Implications**: Improper time validation allows replay attacks using expired assertions or acceptance of future-dated assertions that could enable time-based attacks.

**Attack Vectors**:
- **Clock Skew Exploitation**: Excessive clock skew allowances (>5 minutes) extend the replay window
- **Expired Token Acceptance**: Skipping NotOnOrAfter validation completely
- **NotBefore Bypass**: Ignoring NotBefore attribute allows premature token use

**Real-World Cases**:
- Many implementations allow 5+ minutes of clock skew, creating extended windows for replay attacks
- Some libraries fail to validate timestamps entirely under certain conditions

**Spec-Based Defense**: SAML Core defines: *"The NotBefore attribute defines the earliest time at which the SAML assertion can be considered valid. The NotOnOrAfter attribute specifies the latest time at which the SAML assertion remains valid."* Best practice: 1-minute assertion lifetime, maximum 30 seconds clock skew.

---

### 11. InResponseTo Validation and Replay Protection (SAML Profiles §4.1.4.2)

**Spec Behavior**: In SP-initiated flows, the SAML response contains an InResponseTo attribute referencing the original request ID. The specification allows both SP-initiated and IdP-initiated flows.

**Security Implications**: *"Service providers should validate that the InResponseTo attribute in the SAML response matches the ID of a request that they recently sent."* Without this validation, attackers can replay old responses or use responses from different sessions.

**Attack Vectors**:
- **Replay Attacks**: Reusing valid SAML responses for unauthorized access
- **Session Confusion**: Mixing responses from different authentication sessions
- **IdP-Initiated Flow Risks**: Section 4.1.5 states: *"An SP must ensure that any unsolicited SAML responses received do not contain an InResponseTo value"* - yet IdP-initiated flows are inherently more vulnerable

**Real-World Cases**:
- Multiple SAML libraries had replay protection vulnerabilities
- PyAML2 Issue #333: "saml and replay attack vulnerability"

**Spec-Based Defense**: Implement comprehensive replay protection: *"Validate the InResponseTo attribute in the SAML response against an ID cache to prevent the reuse of assertions."* Additionally: *"When the SP receives a SAML response, it will fetch the stored request ID and relay state values and check them against the received InResponseTo and relay state values."*

---

### 12. Subject Confirmation Method Validation (Sustainsys Advisory GHSA-9475-xg6m-j7pw)

**Spec Requirement**: SAML assertions MUST specify SubjectConfirmation method. RFC 7522 requires: *"The element MUST contain at least one `<SubjectConfirmation>` element that has a Method attribute with a value of 'urn:oasis:names:tc:SAML:2.0:cm:bearer'."*

**Security Implications**: If implementations don't validate the SubjectConfirmation method, attackers can use assertions intended for different confirmation methods (holder-of-key, sender-vouches) as bearer tokens.

**Attack Vectors**:
- **Method Substitution**: Using holder-of-key assertions without possessing the key
- **Confirmation Data Bypass**: Ignoring SubjectConfirmationData restrictions (Recipient, NotOnOrAfter, InResponseTo)

**Real-World Cases**:
- **Sustainsys GHSA-9475-xg6m-j7pw**: "Subject Confirmation Method not Validated" - library failed to enforce bearer method requirements

**Spec-Based Defense**: Strictly validate SubjectConfirmation elements against expected methods and validate all SubjectConfirmationData attributes including Recipient, NotOnOrAfter, and InResponseTo.

---

## Part 4: XML Processing Attacks

### 13. XML External Entity (XXE) Injection (OWASP SAML Security)

**Spec Vulnerability**: XML specification supports external entities—URIs that are dereferenced and included during XML processing. *"By default, many XML processors allow specification of an external entity, a URI that is dereferenced and evaluated during XML processing."*

**Security Implications**: SAML responses are XML documents. If the XML parser processes external entities, attackers can read arbitrary files, perform SSRF, or cause DoS.

**Attack Vectors**:
- **Local File Disclosure**: `<!ENTITY xxe SYSTEM "file:///etc/passwd">` to exfiltrate sensitive files
- **Server-Side Request Forgery (SSRF)**: External entities pointing to internal services
- **Denial of Service**: Billion Laughs attack using recursive entity expansion
- **Out-of-Band Data Exfiltration**: Combining DTD and external entities to exfiltrate data via DNS

**Real-World Cases**:
- **CVE-2016-10149** (pysaml2): XXE allowing remote attackers to read arbitrary files
- **CVE-2017-1000452** (samlify): XXE vulnerability in SAML processing
- **CVE-2024-52806** (simplesamlphp/saml2): Recent XXE vulnerability
- CyberArk Enterprise Password Vault XXE vulnerability

**Spec-Based Defense**: OWASP mandates: *"Always perform schema validation on the XML document prior to using it for any security-related purposes and never allow automatic download of schemas from third party locations."* Disable external entity processing: `parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`

---

### 14. XML Injection in SAML Messages (NCC Group Research 2021)

**Spec Parsing Ambiguity**: XML allows various encoding and structural variations that can be interpreted differently by different parsers.

**Security Implications**: *"XML injection in SAML messages constructed during authentication can modify the structure of the SAML message."* Attackers can inject XML to modify assertions, add attributes, or change authorization decisions.

**Attack Vectors**:
- **Attribute Injection**: Adding malicious attributes like `<Attribute Name="Role"><AttributeValue>Admin</AttributeValue></Attribute>`
- **NameID Manipulation**: Injecting XML to change the authenticated user identity
- **Assertion Injection**: Adding entire assertion elements

**Real-World Cases**:
- NCC Group (March 2021): Documented SAML XML injection allowing identity provider compromise

**Spec-Based Defense**: Input validation and output encoding for all data incorporated into SAML messages. Never construct SAML messages using string concatenation; always use secure XML generation libraries with proper escaping.

---

### 15. Denial of Service via Expensive XML Processing (OASIS Security Considerations)

**Spec Warning**: OASIS explicitly warns: *"The SAML protocol is susceptible to a denial of service (DOS) attack. Handling a SAML request is potentially a very expensive operation, including parsing the request message."*

**Security Implications**: XML parsing, schema validation, signature verification, and encryption operations consume significant computational resources.

**Attack Vectors**:
- **Deeply Nested XML**: Extremely deep nesting causing stack overflow or excessive memory
- **Large Documents**: Multi-megabyte SAML responses exhausting memory
- **Billion Laughs / XML Bomb**: Recursive entity expansion causing exponential resource consumption
- **Compressed Response DoS**: CVE-2025-25293 in ruby-saml: "remote denial-of-service (DoS) flaw when handling compressed SAML responses" (CVSS 7.7)

**Real-World Cases**:
- **CVE-2025-25293**: Ruby-saml DoS via compressed responses

**Spec-Based Defense**: Implement resource limits: maximum document size, maximum nesting depth, entity expansion limits. Rate limiting and proper resource allocation for SAML processing endpoints.

---

## Part 5: Encryption and Confidentiality Issues

### 16. Weak or Missing Assertion Encryption (SAML Core §6, XMLEnc)

**Spec Option**: SAML provides elements for encrypted assertions: `<EncryptedAssertion>`, `<EncryptedAttribute>`, `<EncryptedID>`. However, encryption is optional, not mandatory.

**Security Implications**: *"While the SAML response is base64 encoded so it can travel over HTTP, that doesn't mean it's encrypted."* Without assertion encryption, sensitive attributes (roles, permissions, PII) are exposed to network observers even over HTTPS (which only protects in transit).

**Attack Vectors**:
- **TLS Termination Exposure**: Assertions visible at load balancers, reverse proxies, WAFs
- **Logging and Monitoring**: Base64-decoded assertions logged in plaintext
- **Man-in-the-Middle**: TLS downgrade attacks expose assertion contents

**Real-World Cases**:
- Many implementations don't support encrypted assertions (e.g., "WorkOS do not currently support encrypted response attributes")
- Sensitive attributes (SSN, employee ID, roles) transmitted in plaintext within base64 encoding

**Spec-Based Defense**: SAML 2.0 recommends: *"Assertions may be encrypted via XMLEnc to prevent disclosure of sensitive attributes post transportation."* Best practice: *"Use assertion encryption to envelope all the attributes if confidentiality is required."* However, note: *"XML Encryption is reported to have severe security concerns"* - modern implementations should consider JWE or alternative encryption methods.

---

### 17. XML Encryption Vulnerabilities (XMLEnc Spec)

**Spec Weaknesses**: Multiple academic papers have identified fundamental weaknesses in XML Encryption, including:
- **Padding Oracle Attacks**: CBC mode encryption vulnerable to padding oracle attacks
- **Wrapping Attacks**: Similar to signature wrapping but targeting encrypted elements
- **Algorithm Confusion**: Weak algorithm selection or substitution

**Security Implications**: Even when encryption is used, implementation flaws or spec ambiguities can lead to decryption by attackers.

**Attack Vectors**:
- **CBC Padding Oracle**: Iterative decryption through padding validation responses
- **Algorithm Downgrade**: Forcing use of weak encryption algorithms
- **Key Wrapping Weaknesses**: Vulnerabilities in key encryption mechanisms

**Real-World Cases**:
- Academic research: "XML Encryption is reported to have severe security concerns"
- Multiple padding oracle attacks demonstrated against XML Encryption implementations

**Spec-Based Defense**: Avoid XML Encryption when possible; prefer transport-layer security with TLS 1.3+. If encryption is required, use authenticated encryption (GCM mode), strong key sizes (256-bit), and avoid CBC mode.

---

## Part 6: Implementation and Integration Vulnerabilities

### 18. Parser Differential Attacks (GitHub Security Research 2024-2025)

**Fundamental Issue**: SAML processing involves multiple components with potentially different XML parsers: signature validator, assertion parser, application code. *"Multiple hacking techniques allowed potential attackers to completely bypass XML signature validation while still presenting a valid SAML document to an application."*

**Security Implications**: Attackers exploit subtle differences in how parsers handle edge cases: attribute duplication, namespace handling, character encoding, whitespace, comments.

**Attack Vectors**:
- **Attribute Pollution**: First attribute validates, second attribute used by application
- **Namespace Confusion**: Different namespace resolution between validators and processors
- **Character Encoding**: UTF-8 vs. UTF-16 differences, normalization attacks
- **Whitespace Handling**: Significant vs. insignificant whitespace interpretation differences

**Real-World Cases**:
- **GitHub Blog (2024)**: "Sign in as anyone: Bypassing SAML SSO authentication with parser differentials"
- **CVE-2025-25291/25292** (ruby-saml): "Attackers with a single valid signature from the organization's SAML key can construct SAML assertions and log in as any user"
- PortSwigger toolkit released to identify parser differential vulnerabilities

**Spec-Based Defense**: Use consistent, hardened XML processing throughout the SAML stack. Employ strict schema validation before any processing. *"Never use getElementsByTagName to select security related elements"* - use absolute XPath. Consider SAML security testing tools like PortSwigger's toolkit.

---

### 19. RelayState Parameter Injection and Open Redirect (SAML Bindings §3.4.3)

**Spec Design**: The RelayState parameter preserves application state across the SAML authentication flow. It's passed from SP to IdP and back to SP, but the spec doesn't mandate validation.

**Security Implications**: If RelayState contains URLs and the application doesn't validate them, attackers can inject malicious URLs for open redirect attacks or SSRF.

**Attack Vectors**:
- **Open Redirect**: RelayState pointing to attacker-controlled domain for phishing
- **SSRF**: RelayState pointing to internal services
- **State Confusion**: Manipulating RelayState to cause application logic errors

**Real-World Cases**:
- Common vulnerability in SAML implementations
- Used in phishing campaigns to redirect users after legitimate authentication

**Spec-Based Defense**: OWASP recommends: *"If the contract of the RelayState parameter is a URL, make sure the URL is validated and explicitly on an allowlist."* Never blindly redirect to RelayState values; always validate against known safe destinations.

---

### 20. Single Logout (SLO) Security and Reliability Issues (SAML Profiles §4.4)

**Spec Limitation**: SAML SLO is complex and fragile. *"SLO has some significant restrictions and drawbacks, which make it fragile and challenging to implement. For SLO to work, both the IdP and all SPs must be configured to support SLO; otherwise, various sessions may not be terminated."*

**Security Implications**: Incomplete logout leaves active sessions vulnerable to exploitation. Users assume they're fully logged out when they may not be.

**Attack Vectors**:
- **Partial Logout**: "If only partial logout was possible, the user might assume that the entire SLO process was successful and leave unattended sessions to be exploited"
- **Unresponsive SP**: "An SP might become unresponsive... When this happens, the process breaks down, and the remaining SPs with active sessions don't receive logout requests"
- **SLO Request Forgery**: Attackers sending malicious logout requests

**Real-World Cases**:
- Widespread SLO failures in production deployments
- Security testing reveals many SPs don't implement SLO or implement it incorrectly

**Spec-Based Defense**: Don't rely solely on SLO for security. Implement short session lifetimes, re-authentication for sensitive operations, and session monitoring. Sign SLO requests and responses. Implement graceful degradation when SLO fails.

---

### 21. Certificate and Key Management Vulnerabilities (OASIS Security Considerations §4.3)

**Spec Trust Model**: *"The primary mechanism is for the relying party and asserting party to have a pre-existing trust relationship which typically relies on a Public Key Infrastructure (PKI)."*

**Security Implications**: Weak key management, improper certificate validation, or using the same certificate for multiple purposes creates vulnerabilities.

**Attack Vectors**:
- **Weak Key Compromise**: Reusing keys across signing and encryption
- **Certificate Pinning Failures**: Not validating certificates against expected values
- **Key Rotation Gaps**: No overlap period during certificate rotation causing outages and emergency bypasses
- **Private Key Exposure**: Golden SAML/Silver SAML attacks from stolen signing keys

**Real-World Cases**:
- **Golden SAML** (SolarWinds): Attackers stole ADFS signing certificate
- **Silver SAML** (2024): Exploiting externally generated certificates in Entra ID

**Spec-Based Defense**: OWASP mandates: *"The SP must use a separate certificate and key pair for SAML signing and encryption."* Implement proper key rotation with overlap periods. Store private keys in HSMs. Monitor certificate usage for anomalies.

---

### 22. EntityID Validation and Metadata Trust (SAML Metadata §2.1.1)

**Spec Design**: EntityID is an immutable identifier for SAML entities. Metadata describes entity capabilities and includes certificates.

**Security Implications**: *"If metadata URLs are not used, great care must be taken to assure that an attacker does not convince an SP to trust the wrong certificate."*

**Attack Vectors**:
- **EntityID Spoofing**: IdP using wrong entityID attempting to impersonate another IdP
- **Metadata Manipulation**: Attackers modifying metadata to inject malicious certificates
- **Metadata Injection**: Convincing SP to load attacker-controlled metadata

**Real-World Cases**:
- Misconfigured IdPs accidentally using wrong entityID
- Attacks targeting metadata distribution mechanisms

**Spec-Based Defense**: Validate EntityID matches expected values. Use signed metadata. Fetch metadata over secure channels. Implement metadata freshness validation. The entityID must match in assertions and pre-configured metadata.

---

## Part 7: Latest CVEs and Attack Cases (2024-2025)

### 23. CVE-2025-47949: Samlify Signature Wrapping (January 2025)

**Vulnerability**: Critical Signature Wrapping attack in samlify library (versions < 2.10.0) allowing complete authentication bypass.

**Technical Details**: *"SAML depends on XML signatures to verify who is who in the authentication handshake between identity providers (IdP) and service providers (SP). But when an SAML parser isn't strict about what it checks, attackers can take advantage."*

**Impact**: Complete authentication bypass, arbitrary user impersonation including administrators.

**Attack Mechanism**: Signature Wrapping exploiting parser differential between signature validator and assertion processor.

**Mitigation**: Upgrade to samlify 2.10.0+. Implement strict XML validation with absolute XPath selectors.

---

### 24. CVE-2025-25291/25292/25293: Ruby-SAML Multiple Vulnerabilities (January 2025)

**Vulnerabilities**:
- **CVE-2025-25291**: Authentication bypass allowing login as arbitrary user
- **CVE-2025-25292**: Assertion forgery with single valid signature
- **CVE-2025-25293**: Denial of service via compressed SAML responses (CVSS 7.7)

**Technical Details**: *"Attackers with a single valid signature from the organization's SAML key can construct SAML assertions and log in as any user."*

**Impact**: Complete authentication bypass affecting Ruby-SAML library (used by GitLab and other platforms).

**Attack Mechanism**: Parser differential attacks exploiting attribute pollution, namespace confusion, and canonicalization edge cases.

**Mitigation**: Upgrade to ruby-saml 1.18.0. The fixes address XML parsing strictness and signature validation logic.

---

### 25. CVE-2024-45409: Ruby-SAML Critical Authentication Bypass (CVSS 10.0)

**Vulnerability**: Critical vulnerability allowing attackers to log in as arbitrary users by forging SAML responses.

**Impact**: Affected GitLab and other platforms using ruby-saml, enabling complete account takeover.

**Attack Mechanism**: Forging SAML responses with manipulated assertions bypassing signature validation.

**Real-World Exploitation**: Used in attacks against GitLab instances before patching.

**Mitigation**: Emergency patching required. GitLab released critical security updates.

---

### 26. CVE-2024-4985/9487: GitHub Enterprise SAML Authentication Bypass (2024)

**Vulnerability**: SAML authentication bypass when encrypted assertions are in use.

**Technical Details**: GitHub Security discovered "parser differentials" allowing bypass of XML Signature validation while presenting valid SAML documents.

**Impact**: Complete authentication bypass in GitHub Enterprise instances using SAML SSO.

**Attack Mechanism**: Exploiting encrypted assertion handling to bypass signature validation.

**Mitigation**: GitHub Enterprise security updates. Organizations should audit SAML configurations.

---

### 27. CVE-2024-8698: Keycloak SAML Authentication Vulnerability (2024)

**Vulnerability**: Keycloak SAML authentication at risk from processing vulnerabilities.

**Impact**: Authentication bypass in Keycloak SAML flows.

**Attack Mechanism**: SAML assertion processing flaws allowing bypass of authentication checks.

**Mitigation**: Update to patched Keycloak versions. Review SAML integration security.

---

### 28. Golden SAML and Silver SAML Advanced Persistent Threats

**Golden SAML** (CyberArk 2017):
- Attack: Stealing ADFS private signing key to forge arbitrary SAML tokens
- Impact: Access to any SAML-integrated application with any privileges as any user
- Detection Evasion: Forged assertions appear completely legitimate, bypass MFA
- Real-World: Used in SolarWinds/Solorigate attacks

**Silver SAML** (Semperis 2024):
- Attack: Exploiting Entra ID with externally generated certificates, *"any attacker that obtains the private key of an externally generated certificate can forge any SAML response"*
- Impact: Golden SAML capabilities without ADFS access
- Risk Rating: MODERATE to SEVERE depending on environment
- Defense: Monitor certificate usage, implement certificate pinning, HSM storage for keys

---

## Part 8: Comprehensive Attack-Spec-Defense Mapping

| Attack Type | Spec Vulnerability Exploited | Spec/RFC Reference | Defense Mechanism |
|-------------|------------------------------|-------------------|-------------------|
| XML Signature Wrapping (XSW) | Two-phase processing (validate, then parse) with parser differentials | OASIS Sec Considerations | Absolute XPath, schema validation, unified parser |
| Comment Injection | Canonicalization strips comments before signature verification | xml-exc-c14n algorithm | Remove all comments before processing |
| XXE Injection | XML external entity processing enabled by default | XML 1.0 Spec | Disable external entities and DTDs |
| Replay Attacks | Optional replay protection, bearer tokens | RFC 7522 §5 | InResponseTo validation, ID tracking, short lifetime |
| Audience Restriction Bypass | Optional audience validation in some implementations | RFC 7522 §3 | Strict audience MUST validation |
| Golden SAML | Trust in signing key without runtime validation | SAML trust model | HSM key storage, certificate pinning, anomaly detection |
| Silver SAML | External certificate trust in cloud IdP | Entra ID design | Certificate validation, key monitoring |
| Recipient Confusion | Missing Recipient attribute validation | SAML Core §2.5.1.4 | Validate SubjectConfirmationData Recipient |
| Algorithm Substitution | Self-specified signature algorithm | XMLDSig spec | StaticKeySelector, algorithm allowlist |
| RelayState Injection | Unvalidated state parameter | SAML Bindings §3.4.3 | URL allowlist, state validation |
| Timestamp Bypass | Optional time validation, excessive clock skew | RFC 7522 §3 | Strict NotBefore/NotOnOrAfter, minimal skew |
| SLO Failures | Distributed logout with no guaranteed delivery | SAML Profiles §4.4 | Short sessions, don't rely solely on SLO |
| Parser Differentials | Multiple parsers with different interpretations | Implementation gap | Unified parsing stack, strict validation |
| Attribute Pollution | Duplicate attribute handling ambiguity | XML spec ambiguity | Reject duplicates, first-match validation |
| Metadata Poisoning | Trust in metadata without validation | SAML Metadata | Signed metadata, secure distribution |
| Encryption Weaknesses | Optional encryption, weak XMLEnc | SAML Core §6, XMLEnc | Mandatory encryption, avoid CBC, use TLS 1.3+ |

---

## Part 9: Security Validation Checklist

### Critical MUST-Implement Controls

#### Signature Validation
- [ ] **Absolute XPath Selection**: Never use `getElementsByTagName`; always use absolute XPath expressions (OASIS)
- [ ] **Schema Validation First**: Perform XML schema validation before any security processing (OWASP)
- [ ] **Comment Removal**: Strip all XML comments before processing assertions
- [ ] **StaticKeySelector**: Use pre-configured keys, ignore KeyInfo elements (RFC 7522)
- [ ] **Algorithm Allowlist**: Accept only approved signature algorithms (RSA-SHA256+)
- [ ] **Unified Parser**: Use single parser for signature validation and assertion processing

#### Assertion Validation
- [ ] **Audience Restriction**: MUST reject assertions without matching audience (RFC 7522 §3)
- [ ] **Issuer Validation**: Verify Issuer matches expected IdP EntityID (RFC 7522)
- [ ] **Timestamp Validation**: Enforce NotBefore and NotOnOrAfter with ≤30s clock skew (RFC 7522 §3)
- [ ] **Subject Confirmation**: Validate SubjectConfirmation method is bearer (RFC 7522)
- [ ] **Recipient Validation**: Check SubjectConfirmationData Recipient matches ACS URL
- [ ] **InResponseTo Validation**: Match InResponseTo to stored request ID (SAML Profiles)
- [ ] **Signature Presence**: MUST reject unsigned assertions (RFC 7522)

#### Replay Protection
- [ ] **Assertion ID Tracking**: Maintain cache of used assertion IDs (RFC 7522 §5)
- [ ] **Request ID Correlation**: Store and validate InResponseTo mapping
- [ ] **Short Validity Windows**: Maximum 60-second assertion lifetime
- [ ] **One-Time Use Enforcement**: Reject reused assertion IDs

#### XML Processing Security
- [ ] **Disable External Entities**: `disallow-doctype-decl = true` (OWASP)
- [ ] **Disable DTD Processing**: Prevent XXE and entity expansion attacks
- [ ] **Resource Limits**: Max document size, nesting depth, entity expansions
- [ ] **Input Validation**: Validate all assertion attributes and values

#### Certificate and Key Management
- [ ] **Separate Certificates**: Different certs for signing vs. encryption (OWASP)
- [ ] **Certificate Pinning**: Validate against expected certificates, not KeyInfo
- [ ] **HSM Key Storage**: Store signing keys in hardware security modules
- [ ] **Key Rotation**: Implement rotation with overlap periods
- [ ] **Metadata Signing**: Use signed metadata for certificate distribution

#### Transport Security
- [ ] **TLS 1.2+ Mandatory**: All SAML traffic over modern TLS (minimum 1.2)
- [ ] **Certificate Validation**: Proper TLS certificate validation
- [ ] **HSTS Enforcement**: HTTP Strict Transport Security headers
- [ ] **Secure Cookies**: SameSite=Strict, Secure, HttpOnly flags

#### Additional Security Controls
- [ ] **RelayState Validation**: URL allowlist for RelayState parameters (OWASP)
- [ ] **Rate Limiting**: Prevent DoS on SAML endpoints
- [ ] **Logging and Monitoring**: Log all authentication events, monitor anomalies
- [ ] **Error Handling**: Generic error messages, no information leakage
- [ ] **Session Management**: Short session lifetimes, re-auth for sensitive ops

### High-Risk Configurations to Avoid
- ❌ IdP-initiated SSO (prefer SP-initiated flows)
- ❌ Long assertion validity periods (>60 seconds)
- ❌ Excessive clock skew (>30 seconds)
- ❌ Trusting KeyInfo elements from assertions
- ❌ Using same certificate for signing and encryption
- ❌ Accepting unsigned assertions
- ❌ CBC-mode XML encryption
- ❌ Relying solely on SLO for session termination
- ❌ Unencrypted sensitive attributes
- ❌ Weak signature algorithms (SHA-1, MD5)

---

## Part 10: Specification References and Further Reading

### Primary SAML Specifications
- **SAML 2.0 Core** (OASIS Standard, March 2005): Assertions and Protocols
  - URL: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
  - Defines assertion structure, validation requirements, cryptographic bindings

- **SAML 2.0 Profiles** (OASIS Standard): SSO, SLO, and integration profiles
  - Defines Web Browser SSO, Single Logout, Artifact Resolution profiles

- **SAML 2.0 Bindings** (OASIS Standard): Protocol transport bindings
  - HTTP Redirect, HTTP POST, HTTP Artifact, SOAP bindings

- **Security and Privacy Considerations for SAML V2.0** (OASIS):
  - URL: https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf
  - Comprehensive security guidance, threat model, mitigations

- **RFC 7522**: Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0
  - URL: https://datatracker.ietf.org/doc/html/rfc7522
  - Security considerations for SAML in OAuth flows

### Related XML Security Specifications
- **XML Signature Syntax and Processing** (W3C): XMLDSig specification
- **XML Encryption Syntax and Processing** (W3C): XMLEnc specification
- **Canonical XML** (W3C): Canonicalization algorithms including xml-exc-c14n

### Security Research and Advisories
- **On Breaking SAML: Be Whoever You Want to Be** (USENIX Security 2012)
  - First comprehensive analysis of XSW attacks

- **Golden SAML: Newly Discovered Attack Technique** (CyberArk 2017)
  - Original Golden SAML research

- **Meet Silver SAML** (Semperis 2024)
  - Extension of Golden SAML to cloud environments

- **The Fragile Lock: Novel Bypasses For SAML Authentication** (PortSwigger 2024)
  - Black Hat Europe presentation on parser differentials

- **Sign in as anyone: Bypassing SAML SSO with parser differentials** (GitHub Security)
  - Detailed analysis of parser differential attacks

- **OWASP SAML Security Cheat Sheet**
  - URL: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
  - Practical security implementation guidance

### CVE References (2024-2025)
- CVE-2025-47949 (samlify): Signature Wrapping
- CVE-2025-25291/25292 (ruby-saml): Authentication bypass
- CVE-2025-25293 (ruby-saml): Compressed response DoS
- CVE-2024-45409 (ruby-saml): Critical authentication bypass (CVSS 10.0)
- CVE-2024-4985/9487 (GitHub Enterprise): SAML bypass
- CVE-2024-8698 (Keycloak): SAML authentication vulnerability
- CVE-2017-11428 family: Comment injection vulnerabilities
- CVE-2016-10149 (pysaml2): XXE vulnerability

---

## Appendix: Implementation-Specific Guidance

### For Service Provider (SP) Developers

**Critical Validation Sequence**:
1. Transport-layer validation (TLS certificate, HTTPS)
2. XML structure validation (schema, no XXE, resource limits)
3. Signature validation (algorithm check, certificate pinning, XPath selection)
4. Timestamp validation (NotBefore, NotOnOrAfter, minimal skew)
5. Audience validation (strict matching)
6. Issuer validation (EntityID verification)
7. Replay protection (InResponseTo, assertion ID tracking)
8. Subject confirmation (method, recipient, confirmation data)
9. Business logic validation (attribute checks, authorization)

**Library Selection Criteria**:
- Recent security audit (within 12 months)
- Active maintenance (updates within 3 months)
- CVE response time (<30 days)
- Parser differential testing
- Comprehensive validation by default (no insecure convenience modes)

### For Identity Provider (IdP) Operators

**Key Management**:
- Store signing keys in HSM (hardware security module)
- Separate signing and encryption certificates
- Implement key rotation with 30-day overlap
- Monitor certificate usage for Golden/Silver SAML indicators
- Use 4096-bit RSA or 256-bit ECDSA

**Assertion Generation**:
- Minimal lifetime: 60 seconds maximum
- Include Audience restriction for each SP
- Use NotBefore and NotOnOrAfter
- Generate cryptographically random assertion IDs
- Sign entire Response and Assertion (double signature)
- Encrypt sensitive attributes

**Monitoring and Detection**:
- Log all assertion issuance with SP, user, timestamp
- Alert on unusual patterns (excessive assertions, new SPs, unusual users)
- Monitor certificate usage for key compromise indicators
- Track assertion validity periods for anomalies

---

## Conclusion: The Meta-Structure of SAML Security

SAML's security challenges stem from fundamental architectural decisions:

1. **XML Complexity**: The choice of XML as the foundation introduces inherent parser differential risks. The specification assumes consistent XML processing, but real-world implementations vary.

2. **Distributed Trust**: SAML's federated architecture distributes trust across IdPs, SPs, and metadata systems. Each trust boundary is an attack surface.

3. **Backward Compatibility**: SAML 2.0 maintains compatibility with earlier versions and various XML standards, inheriting their security limitations.

4. **Optional Security**: Many critical security controls (replay protection, encryption, strict validation) are optional or implementation-dependent, creating a "race to the bottom" in security.

5. **Bearer Token Model**: The fundamental bearer token design lacks proof-of-possession, making token theft highly impactful.

**The Path Forward**:
Modern authentication should consider SAML's lessons:
- **Simpler formats** (JSON, JWT) reduce parser differential attack surface
- **Mandatory security controls** (no optional crypto)
- **Proof-of-possession tokens** (DPoP, certificate-bound tokens)
- **Built-in revocation** (token introspection, short lifetimes)

For existing SAML deployments, defense requires **defense in depth**: strict validation at every layer, continuous monitoring, minimal trust, and assumption of breach. The specification provides security guidance, but implementations must go beyond minimum requirements to achieve actual security.

---

**Document Version**: 1.0
**Analysis Date**: February 2025
**Next Review**: Quarterly (or upon major CVE disclosure)
**Maintained By**: Web Spec Security Analysis Project

---

## Sources

- [Sign in as anyone: Bypassing SAML SSO authentication with parser differentials - GitHub Blog](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/)
- [GitHub Uncovers New ruby-saml Vulnerabilities](https://thehackernews.com/2025/03/github-uncovers-new-ruby-saml.html)
- [SSO Protocol Security: Critical Vulnerabilities in SAML, OAuth, OIDC & JWT (2025)](https://guptadeepak.com/security-vulnerabilities-in-saml-oauth-2-0-openid-connect-and-jwt/)
- [GitHub Enterprise SAML Authentication Bypass (CVE-2024-4985 / CVE-2024-9487)](https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass)
- [The Fragile Lock: Novel Bypasses For SAML Authentication - PortSwigger Research](https://portswigger.net/research/the-fragile-lock)
- [CVE-2025-47949 - samlify SAML SSO Bypass](https://www.endorlabs.com/learn/cve-2025-47949-reveals-flaw-in-samlify-that-opens-door-to-saml-single-sign-on-bypass)
- [New Silver SAML Attack Evades Golden SAML Defenses](https://thehackernews.com/2024/02/new-silver-saml-attack-evades-golden.html)
- [SAML authentication broken almost beyond repair - CSO Online](https://www.csoonline.com/article/4105030/saml-authentication-broken-almost-beyond-repair.html)
- [Identity Theft Attacks on Modern SSO Systems - BlackHat 2018](https://i.blackhat.com/us-18/Thu-August-9/us-18-Ludwig-Identity-Theft-Attacks-On-SSO-Systems.pdf)
- [Novel Bypasses for SAML Authentication - BlackHat EU 2025](https://i.blackhat.com/BH-EU-25/eu-25-Fedotkin-TheFragileLock.pdf)
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [Secure SAML validation to prevent XML signature wrapping attacks](https://arxiv.org/pdf/1401.7483)
- [XML Signature Wrapping vulnerability in SAML protocol](https://support.microfocus.com/kb/doc.php?id=7011305)
- [XML Signature Wrapping in Samlify](https://www.whitehats.nl/en/blog/xml-signature-wrapping-in-samlify)
- [SAML's signature problem: It's not you, it's XML - WorkOS](https://workos.com/blog/saml-signature-problem)
- [On Breaking SAML: Be Whoever You Want to Be - USENIX 2012](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf)
- [SAML Specifications - OASIS](https://saml.xml.org/saml-specifications)
- [RFC 7522 - SAML 2.0 Profile for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc7522)
- [Security and Privacy Considerations for SAML V2.0 - OASIS](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf)
- [Golden SAML: Newly Discovered Attack Technique - CyberArk](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps)
- [Meet Silver SAML: Golden SAML in the Cloud - Semperis](https://www.semperis.com/blog/meet-silver-saml/)
- [SAML Consumer Service XXE - Acunetix](https://www.acunetix.com/vulnerabilities/web/saml-consumer-service-xml-entity-injection-xxe/)
- [XML External Entity (XXE) Injection in ruby-saml - Snyk](https://security.snyk.io/vuln/SNYK-RUBY-RUBYSAML-20232)
- [Common SAML security vulnerabilities - WorkOS](https://workos.com/guide/common-saml-security-vulnerabilities)
- [Fun with SAML SSO vulnerabilities and footguns - WorkOS](https://workos.com/blog/fun-with-saml-sso-vulnerabilities-and-footguns)
- [A Breakdown of the New SAML Authentication Bypass Vulnerability - Okta](https://developer.okta.com/blog/2018/02/27/a-breakdown-of-the-new-saml-authentication-bypass-vulnerability)
- [SAML XML Injection - NCC Group Research](https://research.nccgroup.com/2021/03/29/saml-xml-injection/)
- [SAML Replay Attacks - Compile7](https://compile7.org/saml/docs/security/replay-attacks/)
- [The Dangers of SAML IdP-Initiated SSO - IdentityServer](https://www.identityserver.com/articles/the-dangers-of-saml-idp-initiated-sso)
- [SAML Security Considerations - WorkOS Docs](https://workos.com/docs/sso/saml-security)
- [Understanding SAML Request Signing and Response Encryption - WorkOS](https://workos.com/blog/saml-request-signing-and-response-encryption)
- [The Challenge of Building SAML Single Logout - IdentityServer](https://www.identityserver.com/articles/the-challenge-of-building-saml-single-logout)
- [Single Logout Explained - FusionAuth](https://fusionauth.io/blog/single-sign-on-vs-single-log-out)
