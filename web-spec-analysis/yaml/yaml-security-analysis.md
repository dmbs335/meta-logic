# YAML Security Analysis

> **Analysis Target**: YAML 1.2.2 Specification, RFC 9512 (YAML Media Type)
> **Methodology**: Spec-based analysis + CVE/attack research cross-mapping
> **Latest Cases**: CVE-2025-55182, CVE-2025-68613, CVE-2022-1471
> **Date**: February 2026

---

## Executive Summary

YAML's specification lacks a dedicated security section and contains no normative security requirements (MUST/MUST NOT). Three fundamental attack categories: (1) **RCE** via tag-based object instantiation, (2) **DoS** through recursive anchors / exponential expansion (Billion Laughs), (3) **type confusion** from implicit coercion and YAML 1.1/1.2 inconsistencies. RFC 9512 §4 acknowledges risks but provides only advisory guidance. 12 vulnerability classes mapped across 4 languages.

---

## Part I: Specification Vulnerabilities

### 1. Tag System — Attacker-Controlled Type Resolution (YAML §2.4, RFC 9512 §4.1)

Tags serve as type identifiers — spec **does not restrict which types can be instantiated**. Data payloads dictate processing logic (fundamental anti-pattern). Python: `!!python/object/apply:os.system` → RCE. Java: `!!javax.script.ScriptEngineManager` → remote class loading.

**CVEs**: CVE-2022-1471 (SnakeYAML, CVSS 9.8), CVE-2017-18342 (PyYAML), CVE-2025-68613 (n8n, CVSS 9.9).

RFC 9512 §4.1: *"Care should be used when using YAML tags"* — advisory only, no MUST requirement.

**Defense**: `yaml.safe_load()` (Python), SnakeYAML 2.0+ `SafeConstructor` (Java), `YAML.safe_load()` (Ruby), `yaml.safeLoad()` (JS).

### 2. Anchor/Alias — Recursive Reference Exploitation (YAML §3.2.2.2, RFC 9512 §4.2)

No spec-level limit on recursion depth or expansion size. Anchors need not be unique. **Billion Laughs**: 9-level nested aliases → 3.4 billion elements → gigabytes of memory. **Cyclic references**: `&cycle next: *cycle` → infinite loops.

**CVE-2019-11253** (Kubernetes): YAML bomb crashed kube-apiserver.

**Defense**: Recursion depth limits, cycle detection, memory/time limits, StrictYAML (rejects anchors entirely).

### 3. Schema Type Coercion (YAML §10)

Three schemas (Failsafe, JSON, Core) with different type resolution. Most libraries default to permissive Core Schema. `yes`/`no` → boolean, `0123` → octal 83 (YAML 1.1). **Norway Problem**: country code `no` parsed as `false`.

YAML 1.2 restricted booleans to `true/false` only, but most libraries still default to YAML 1.1 behavior.

**Defense**: Quote all strings, use JSON/Failsafe Schema, enforce YAML 1.2, validate types after parsing.

### 4. No Security Boundaries (YAML §3.1)

Three-stage pipeline (Parse → Compose → Construct) has no concept of trusted vs untrusted input. All input proceeds through full construction to native objects unless implementation restricts it.

---

## Part II: Language-Specific Exploitation

### 5. Deserialization Gadgets

| Language | Unsafe API | Safe API | Key CVE |
|----------|-----------|----------|---------|
| Python (PyYAML) | `yaml.load()` | `yaml.safe_load()` | CVE-2017-18342, CVE-2020-1747 |
| Java (SnakeYAML) | `new Yaml(new Constructor())` | `new Yaml()` (2.0+) | CVE-2022-1471 (CVSS 9.8) |
| Ruby (Psych) | `YAML.load()` | `YAML.safe_load()` | Rails cookie RCE |
| JavaScript (js-yaml) | `yaml.load()` | `yaml.safeLoad()` | CVE-2013-4660 |

SnakeYAML CVE-2022-1471 affected Spring Boot ecosystem-wide (SnakeYAML bundled in `spring-boot-starter`). Gadget chains from Spring, Jackson libraries achieved RCE.

### 6. Merge Key Configuration Injection

YAML 1.1 merge keys (`<<`) silently inherit properties. In CI/CD pipelines, insecure defaults (admin_access, debug_mode) propagate across contexts without developers realizing. Attacker with write access to shared YAML can inject malicious settings.

**Defense**: Avoid merge keys across security boundaries. Explicit security-critical settings per context.

### 7. YAML 1.1 vs 1.2 Security Gap

| Feature | YAML 1.1 | YAML 1.2 | Impact |
|---------|----------|----------|--------|
| Booleans | yes/no/on/off/true/false | true/false only | Config confusion |
| Octal | `0123` → 83 | `0123` → 123 | Permission manipulation |
| Sexagesimal | `60:30` → 3630 | `60:30` → string | Unexpected numeric parsing |
| Merge keys | Supported | Not in spec | Inheritance confusion |

Libraries defaulting to 1.1: PyYAML, SnakeYAML. Libraries supporting 1.2: js-yaml, ruamel.yaml.

---

## Part III: Latest CVEs (2024-2025)

| CVE | Year | Component | CVSS | Attack | Fix |
|-----|------|-----------|------|--------|-----|
| CVE-2025-68613 | 2025 | n8n | 9.9 | YAML expression injection → sandbox escape → RCE | Update to patched version |
| CVE-2025-55182 | 2025 | React Server Components | 9.8 | Unsafe deserialization (same pattern as YAML) | Update React |
| CVE-2022-1471 | 2022 | SnakeYAML | 9.8 | Constructor deserialization → RCE | Upgrade to 2.0+ |
| CVE-2020-1747 | 2020 | PyYAML | 9.8 | Arbitrary code execution | Use safe_load() |
| CVE-2019-11253 | 2019 | Kubernetes | 7.5 | YAML bomb (Billion Laughs) → DoS | Update Kubernetes |

---

## Part IV: Specification Gaps

**YAML 1.2.2 has no Security Considerations section.** RFC 9512 §4 covers arbitrary code execution, resource exhaustion, streams, and boolean issues — but all guidance is **informative only**, no normative keywords.

**Safe YAML alternatives**: StrictYAML (no tags, no anchors, no implicit typing, all values as strings), JSON (no code execution, strict typing), TOML (comments, explicit typing, no code execution).

---

## Attack-Spec-Defense Mapping

| Attack | Spec Feature | Severity | Defense |
|--------|-------------|----------|---------|
| RCE via tags | Tag-based object instantiation (§2.4) | Critical | Safe loaders, whitelist tags |
| Billion Laughs | Unlimited anchor expansion (§3.2.2.2) | High | Recursion/size limits |
| Cyclic reference DoS | Unrestricted aliases (§3.2.2.2) | High | Cycle detection |
| Type confusion | Implicit coercion (§10) | Medium | Quote strings, JSON schema |
| Boolean confusion | YAML 1.1 yes/no/on/off | Medium | Enforce YAML 1.2 |
| Config injection | Merge keys inheritance | Medium | Explicit config, no merge keys |
| Parser differential | YAML 1.1 vs 1.2 | Medium | Standardize on YAML 1.2 |

---

## Sources

**Specs**: [YAML 1.2.2](https://yaml.org/spec/1.2.2/) | [RFC 9512](https://datatracker.ietf.org/doc/html/rfc9512)

**CVEs**: [CVE-2022-1471 (SnakeYAML)](https://github.com/advisories/GHSA-mjmj-j48q-9wg2) | [CVE-2025-68613 (n8n)](https://www.resecurity.com/blog/article/cve-2025-68613-remote-code-execution-via-expression-injection-in-n8n-2) | [CVE-2025-55182 (React2Shell)](https://www.recordedfuture.com/blog/critical-react2shell-vulnerability) | [CVE-2019-11253 (Kubernetes)](https://github.com/kubernetes/kubernetes/issues/83253)

**Research**: [The YAML Document from Hell](https://ruudvanasseldonk.com/2023/01/11/the-yaml-document-from-hell) | [StrictYAML](https://github.com/crdoconnor/strictyaml) | [YAML Anchors in CI/CD](https://xygeni.io/blog/yaml-anchors-and-aliases-the-overlooked-attack-surface-in-cicd/) | [OWASP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
