# JSON Specification Security Analysis

> **Analysis Target**: RFC 8259 (JSON Data Interchange Format), ECMA-404 (JSON Data Interchange Syntax)
> **Methodology**: Spec analysis + CVE/attack research cross-mapping
> **Latest Cases**: CVE-2024-43485 (System.Text.Json), CVE-2024-21907 (Newtonsoft.Json), CVE-2024-57699 (Json-smart)
> **Date**: February 2026

---

## Executive Summary

JSON security issues arise from **specification design decisions** that prioritize flexibility over determinism. RFC 8259's "unpredictable" and "implementation may" language grants permission for parser divergence, which attackers exploit in multi-component architectures. Core attack surfaces: (1) **duplicate key precedence** inconsistencies across parsers, (2) **polymorphic deserialization RCE** via library-specific type extensions (`$type`, `@class`), (3) **algorithmic complexity DoS** from unlimited nesting/size, (4) **Unicode handling** differences enabling key collision, (5) **parser interoperability** gaps (comments, BOM, special values). 13 vulnerability classes mapped.

---

## Part I: Specification Ambiguities

### 1. Duplicate Key Precedence (RFC 8259 §4)

RFC 8259: *"behavior of software that receives [non-unique names] is unpredictable."* ECMA-404 is silent on duplicates. Parsers diverge: Python stdlib (last-key), Go jsonparser (first-key), Java json-iterator (first-key read, last-key serialize).

**Attack** (Bishop Fox): Validation Service (last-key) validates `quantity: 1000` as positive → Payment Service (first-key) charges for `quantity: 1` → Fulfillment ships 1000 units.

**Defense**: Configure parsers to reject duplicates. Use single parser across validation and processing.

### 2. Unicode Handling — Unpaired Surrogates (RFC 8259 §8.2)

RFC 8259: *"An implementation may not be able to process... unpaired UTF-16 surrogates."* Parsers: Python ujson truncates, some replace with U+FFFD, strict parsers reject. `"superadmin\ud888"` truncated to `"superadmin"` → key collision → privilege escalation in multi-language services.

**Defense**: Replace invalid Unicode with U+FFFD (never truncate). Reject unpaired surrogates at API gateway.

### 3. eval() Prohibition (RFC 8259 §12)

RFC 8259: *"using eval()... constitutes an unacceptable security risk."* Advisory only — can't enforce. JSON is JavaScript subset → `eval('(' + jsonString + ')')` naturally parses but executes injected code.

**Defense**: `JSON.parse()` only. CSP `script-src` restrictions. Never eval/Function() untrusted data.

### 4. Number Precision Undefined (RFC 8259 §6)

RFC 8259 recommends IEEE 754 double precision but allows implementation-defined limits. Go jsonparser returns `0` for overflows. Silent rounding: `1.000000000000000005` → `1.0`. Integer overflow in 32-bit: large values wrap negative.

**Defense**: Validate ranges before parsing. Arbitrary-precision types for finance (BigDecimal). Reject out-of-range values.

---

## Part II: Deserialization Vulnerabilities

### 5. Polymorphic Deserialization RCE — Json.NET (External to Spec)

RFC 8259 defines no type system. Json.NET adds `$type` field for object-oriented deserialization. `TypeNameHandling.All` + untrusted input → attacker specifies `ObjectDataProvider` → `Process.Start("calc.exe")` → RCE.

**BlackHat USA 2017** ("Friday the 13th: JSON Attacks"): Multiple .NET gadget chains documented.

**CVE-2024-21907**: Stack overflow via crafted type chains.

**Defense**: Never `TypeNameHandling.All`/`Auto` with untrusted input. Use `TypeNameHandling.None` (default). Whitelist types via `SerializationBinder`.

### 6. Jackson Polymorphic Deserialization RCE

Jackson `enableDefaultTyping()` + `@class` annotation → `JdbcRowSetImpl` gadget → JNDI lookup to attacker LDAP → malicious Java object → RCE.

**Defense**: Avoid `enableDefaultTyping()`. Use explicit `@JsonTypeInfo` + `@JsonSubTypes`. `PolymorphicTypeValidator` to restrict deserialization.

### 7. Deep Nesting DoS (RFC 8259 §9, CVE-2024-43485)

RFC 8259 permits but doesn't require depth limits. Stack-based parsers: deep recursion → stack overflow. Hash collision: 100k+ duplicate keys → O(n²) lookup.

**CVE-2024-43485** (System.Text.Json): `[ExtensionData]` property → O(n²) on nested objects. **CVE-2024-21907** (Newtonsoft.Json): Stack overflow from high nesting. **CVE-2024-57699** (Json-smart): Stack exhaustion from opening braces.

**Defense**: `MaxDepth = 64`, reject payloads >1MB, streaming parsers for large data, monitor deserialization time.

---

## Part III: Interoperability Vulnerabilities

### 8. Comment Support (RFC 8259 Violation)

RFC 8259 grammar excludes comments. GSON, Newtonsoft.Json, Go jsonparser support `/* */` or `//`. Comment-supporting parser removes comment → key collision or logic divergence vs strict parser.

**Defense**: Strict RFC 8259 parsers in production. Reject `/*`, `//` patterns at API gateway.

### 9. BOM Injection (RFC 8259 §8.1)

RFC 8259: *"MUST NOT add a byte order mark."* Some parsers accept BOM, others reject → schema validation bypass or processing inconsistency.

**Defense**: Reject JSON starting with BOM bytes `0xEF 0xBB 0xBF` at ingress.

### 10. Infinity/NaN Type Juggling (RFC 8259 §6)

RFC 8259 doesn't define `Infinity`, `NaN`. JavaScript `JSON.stringify()` converts to `null`. Lenient parsers accept as numbers → `credit_limit: Infinity` always passes comparison checks.

**Defense**: Reject literal Infinity/NaN. Schema validation for number types.

---

## Part IV: Injection Attacks

### 11. JSONP Callback XSS (Legacy, Not RFC 8259)

Unsanitized `callback` parameter → `alert(document.cookie);//({"user":"alice"})` → XSS + CSP bypass if endpoint whitelisted.

**Defense**: Deprecate JSONP, use CORS. If required: whitelist callback names `^[a-zA-Z0-9_]+$`.

### 12. Server-Side JSON Injection

String concatenation of user input into JSON → `"admin", "role": "superadmin"` → duplicate key exploitation.

**Defense**: Use library serialization (`JSON.stringify()`, `JsonSerializer`). Never concatenate user input.

### 13. Client-Side JSON Injection — DOM XSS

JSON embedded in `<script>` tags without HTML encoding → `</script><script>alert(1)` breaks out of context.

**Defense**: HTML-encode `<`, `>`, `&` before embedding. CSP `script-src 'self'`.

---

## Parser Behavior Reference

| Parser | Language | Duplicate Key | Truncates Surrogates | Comments |
|--------|----------|--------------|---------------------|----------|
| Python stdlib | Python | Last-key | No (U+FFFD) | No |
| Go encoding/json | Go | Last-key | No | No |
| Go jsonparser | Go | First-key | No | Yes |
| Python ujson | Python | Last-key | Yes | No |
| Java GSON | Java | Last-key | No | Yes (opt) |
| C# Newtonsoft | C# | Last-key | No | Yes (opt) |
| Java json-iterator | Java | First read, last serialize | No | No |

---

## CVE Summary (2024-2025)

| CVE | Component | Attack | Fix |
|-----|-----------|--------|-----|
| CVE-2024-43485 | System.Text.Json (.NET) | `[ExtensionData]` O(n²) DoS | .NET 6.0.35, 8.0.10 |
| CVE-2024-21907 | Newtonsoft.Json | Stack overflow from deep nesting | v13.0.1 |
| CVE-2024-57699 | Json-smart (Java) | Stack exhaustion from `{{{{...` | v2.5.2 |

---

## Attack-Spec-Defense Mapping

| Attack | Spec Reference | Defense |
|--------|---------------|---------|
| Duplicate key exploit | RFC 8259 §4 ("unpredictable") | Reject duplicates, single parser |
| Character truncation | RFC 8259 §8.2 (unpaired surrogates) | U+FFFD replacement, reject surrogates |
| eval() injection | RFC 8259 §12 (advisory only) | `JSON.parse()`, CSP |
| Number overflow/underflow | RFC 8259 §6 (impl-defined limits) | Validate ranges, arbitrary-precision |
| Polymorphic RCE | N/A (library extension) | Never `TypeNameHandling.All`, whitelist types |
| Deep nesting DoS | RFC 8259 §9 (depth limits optional) | `MaxDepth = 64`, size limits |
| Comment bypass | N/A (RFC violation) | Strict RFC parsers |
| BOM injection | RFC 8259 §8.1 (MUST NOT) | Reject BOM at ingress |
| Infinity/NaN juggling | RFC 8259 §6 (undefined) | Reject special values |
| JSONP callback XSS | N/A (legacy) | Deprecate JSONP, use CORS |
| JSON injection | RFC 8259 §7 (assumes proper escaping) | Library serialization, never concatenate |

---

## Sources

**Specs**: [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259) | [ECMA-404](https://ecma-international.org/publications-and-standards/standards/ecma-404/)

**Research**: [Bishop Fox JSON Interoperability](https://bishopfox.com/blog/json-interoperability-vulnerabilities) | [BlackHat 2017 "Friday the 13th"](https://blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf) | [PortSwigger JSON Parser Risks](https://portswigger.net/daily-swig/research-how-json-parsers-can-create-security-risks-when-it-comes-to-interoperability) | [GitHub Unsafe Deserialization](https://github.blog/security/vulnerability-research/execute-commands-by-sending-json-learn-how-unsafe-deserialization-vulnerabilities-work-in-ruby-projects/)

**CVEs**: [CVE-2024-43485](https://vulert.com/vuln-db/CVE-2024-43485) | [CVE-2024-21907](https://www.cvedetails.com/cve/CVE-2024-21907/) | [CVE-2024-57699](https://www.wiz.io/vulnerability-database/cve/cve-2024-57699)
