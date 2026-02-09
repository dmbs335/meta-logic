# JavaScript Language Security Analysis: Spec & Implementation Review

> **Analysis Target**: ECMAScript (ECMA-262), V8, SpiderMonkey, JavaScriptCore
> **Sources**: ECMA-262 (2024-2026), TC39, V8/SpiderMonkey/JSCore internals, BlackHat/DEF CON 2024-2025
> **Date**: February 2026

---

## Executive Summary

JavaScript's security challenges stem from three layers: **specification-level** (dynamic typing, prototype inheritance, implicit coercion), **implementation-level** (JIT type confusion, memory corruption), and **ecosystem-level** (npm supply chain, framework vulnerabilities). Key 2025 findings: 8 V8 zero-days (50% of Chrome exploits), React2Shell CVE-2025-55182 (CVSS 10.0, pre-auth RCE), and persistent prototype pollution across npm.

---

## Part I: ECMA-262 Specification Security

### 1. Dynamic Type System & Implicit Coercion (§7.1)

ECMA-262 allows implicit type coercion in nearly all mixed-type operations via `ToNumber`, `ToString`, `ToBoolean`, `ToPrimitive`.

**Attack Vectors**:
- **Validation bypass**: Objects with custom `valueOf()`/`toString()` pass numeric checks but inject SQL via string coercion
- **Loose equality exploits**: `"0" == 0`, `null == undefined`, `[] == false` — 34% of JS security vulns involve `==`
- **NoSQL injection**: Array `toString()` coercion (`["admin","user"]` → `"admin,user"`)

**Defense**: Always use `===`. Explicit `typeof` checks before security-critical operations.

### 2. Prototype Chain Pollution (§6.1.7, §10.1)

Every object inherits from `Object.prototype` via `[[Prototype]]`. Polluting `Object.prototype` affects all objects globally.

**Attack Vectors**:
- `__proto__` pollution via vulnerable deep merge: `JSON.parse('{"__proto__": {"isAdmin": true}}')` → merge → all objects gain `isAdmin`
- `constructor.prototype` pollution (bypasses `__proto__` filters)
- Client-side prototype pollution → DOM XSS: `?__proto__[transport_url]=data:,alert(1)`

**CVEs**: CVE-2024-21529 (dset, 80K+/week), CVE-2024-21505 (web3-utils), CVE-2025-55182 (React, prototype→RCE)

**Defense**: `Object.create(null)` for maps, `Object.freeze(Object.prototype)`, filter `__proto__`/`constructor`/`prototype` keys in JSON reviver.

### 3. Dynamic Code Execution: eval & Function (§19.2.1, §20.2.1.1)

`eval()` and `Function()` constructor parse and execute arbitrary strings as code.

**CVEs**: CVE-2025-12735 (expr-eval, CVSS 9.8, 80K+/week), CVE-2025-55182 (React: `constructor.constructor('malicious')()`), CVE-2024-4367 (PDF.js)

**Defense**: Never eval user input. Strict mode limits eval scope leakage. Use AST-based expression evaluators (jsep).

### 4. Scope Chain & Variable Hoisting (§9.1, §9.2)

`var` hoists to function scope; `let`/`const` have block scope with Temporal Dead Zone. Hoisting enables variable shadowing and closure capture bugs.

**Defense**: Use `let`/`const` exclusively. Enable strict mode to prevent implicit globals.

### 5. The `with` Statement (§B.3.2 — Deprecated)

`with` extends scope chain with object properties, enabling variable hijacking: `with(userObj) { if(adminMode) grantPrivileges(); }` — `adminMode` resolves to `userObj.adminMode`.

**Defense**: Strict mode prohibits `with` entirely.

### 6. Strict Mode Security Improvements (§11.2.2)

Strict mode prevents: implicit globals, eval scope leakage, `with` statement, duplicate parameters, silent assignment errors. `this` is `undefined` in plain functions (not global object).

### 7. `this` Binding Confusion (§9.2.1.2)

`this` determined by call-site, not lexically. Method extraction + `call()`/`apply()` with different context enables privilege escalation.

**Defense**: Arrow functions (lexical `this`) or explicit `.bind()`.

### 8. ReDoS (§22.2)

ECMA-262 mandates no time complexity bounds for regex. Nested quantifiers cause catastrophic backtracking: `/(a+)+$/` with `"a".repeat(25)+"!"` → exponential time.

**CVEs**: CVE-2022-31129 (moment.js), CVE-2020-28500 (lodash, 100M+/week), CVE-2022-25927 (ua-parser-js)

**Defense**: Avoid nested quantifiers. Use Worker threads with timeouts. Safe-regex linting.

### 9. JSON.parse & Prototype Pollution (§25.5.1)

`JSON.parse()` itself doesn't pollute prototypes — `__proto__` becomes a regular property. But subsequent merge/copy operations trigger pollution.

**Defense**: JSON reviver filtering dangerous keys. Use `Map` instead of plain objects.

---

## Part II: Engine Implementation Vulnerabilities

### 10. JIT Type Confusion (V8 TurboFan, SpiderMonkey IonMonkey, JSC DFG/FTL)

JIT compilers speculate on object shapes. When assumptions are violated after optimization but de-optimization fails → type confusion → OOB memory access.

**Techniques**: Object shape manipulation (delete+re-add properties after JIT training), inline cache poisoning via Proxy, concurrent JIT compilation race conditions.

**CVEs**: CVE-2025-6554 (V8 type confusion, ITW), CVE-2025-6558 (V8 memory corruption + sandbox bypass, ITW), CVE-2025-10585 (V8/Wasm type confusion, ITW), CVE-2024-5830 (V8 type confusion)

**Defense**: `--untrusted-code-mitigations` (default since v6.4), V8 Sandbox, keep engines updated.

### 11. Spectre-Style Side-Channels

Speculative execution in JIT code leaks data through cache timing. Attacker measures `timingArray[secretValue * 4096]` access times.

**Mitigations**: Reduced `performance.now()` precision (100μs), Site Isolation (separate processes per origin), V8 index masking.

### 12. Memory Safety: UAF & Buffer Overflows

GC bugs, JIT compiler errors, or native binding flaws cause use-after-free and buffer overflows → arbitrary R/W → RCE. CVE-2019-9810 (SpiderMonkey bounds check optimization).

**Defense**: V8 Sandbox, guard pages, pointer authentication (ARM64), regular engine updates.

### 13. WebAssembly Sandbox Escape

Wasm-JS boundary bugs enable sandbox escape. CVE-2023-6699 (V8 Wasm bounds checking), October 2025 Chrome JSPI stack-switching bug (full arbitrary code execution), Wasmtime externref regression, Wasmer WASI path traversal.

**Defense**: V8 Sandbox, Wasm runtime updates, reference type validation at boundaries.

### 14. Object Shape Optimization Exploits

V8 "hidden classes" (Maps) enable fixed-offset property access. Shape manipulation after JIT training → type confusion (property offset swap).

---

## Part III: Cross-Cutting Security Patterns

### 15. Node.js Specific Risks

- **Prototype pollution → RCE**: CVE-2025-55182 (React Server Components, CVSS 10.0) — single HTTP request, no auth needed, 200K+ vulnerable apps, exploited ITW (PeerBlight, CowTunnel, ZinFoq malware)
- **Event loop blocking**: ReDoS on single-threaded server blocks all requests
- **Path traversal**: `res.sendFile(__dirname + '/files/' + userInput)` without validation

**Defense**: Freeze prototypes, `path.resolve()` + startsWith check, Worker threads for CPU-intensive ops.

### 16. Browser DOM XSS

- Prototype pollution → DOM XSS via gadgets (`config.transport_url` → script injection)
- Template literal injection: `` `<h1>Hello ${location.hash.slice(1)}</h1>` ``
- `document.write()` with untrusted data

**Defense**: `textContent` over `innerHTML`, DOMPurify, CSP with nonces.

### 17. npm Supply Chain

143% increase in ReDoS exploits (2018). Thousands of packages affected by prototype pollution.

| CVE | Package | Type | CVSS | Downloads |
|-----|---------|------|------|-----------|
| CVE-2025-12735 | expr-eval | eval RCE | 9.8 | 80K+/week |
| CVE-2024-21529 | dset | Prototype pollution | High | Unknown |
| CVE-2024-21505 | web3-utils | Prototype pollution | High | Crypto ecosystem |
| CVE-2022-31129 | moment.js | ReDoS | Moderate | 12M+/week |
| CVE-2020-28500 | lodash | ReDoS | High | 100M+/week |

**Defense**: `npm audit`, lock files, `npm ci`, Snyk/Dependabot monitoring.

---

## Part IV: 2024-2025 Vulnerability Landscape

8 Chrome zero-days in 2025, 4 targeting V8 (50%). Exploitation trends: JIT type confusion (50% of Chrome exploits), prototype pollution chains (client→XSS, server→RCE), Wasm boundary bugs, npm supply chain.

**Emerging patterns**: AI-generated code introducing eval/insecure deserialization, serverless function prototype pollution, Deno (secure-by-default permissions) vs Bun (less mature security), Web3/crypto library exploits.

---

## Part V: Attack-Spec-Defense Mapping

| Attack | Spec/Engine Behavior | ECMA-262 § | Defense |
|--------|---------------------|------------|---------|
| Prototype pollution | Dynamic property addition, `__proto__` | §6.1.7, §10.1 | `Object.create(null)`, freeze prototypes, filter keys |
| JIT type confusion | Speculative optimization on shapes | Implementation | `--untrusted-code-mitigations`, updates |
| eval injection | Dynamic code execution from strings | §19.2.1 | Avoid eval, strict mode, AST evaluation |
| Type coercion bypass | Implicit ToNumber/ToString | §7.1 | `===`, explicit type checks |
| ReDoS | Backtracking regex, no complexity bounds | §22.2 | Non-backtracking patterns, safe-regex, timeout |
| Scope confusion | var hoisting, with statement | §9.1, §B.3.2 | Strict mode, let/const |
| DOM XSS | innerHTML, document.write | W3C DOM | DOMPurify, textContent, CSP |
| Server-side RCE | Prototype pollution + Function constructor | §6.1.7 + §20.2.1.1 | Freeze prototypes, no dynamic code execution |
| Wasm sandbox escape | Wasm-JS boundary bugs | Implementation | V8 sandbox, runtime updates |
| this binding confusion | Dynamic this resolution | §9.2.1.2 | Arrow functions, explicit bind() |

---

## CVE Reference Table

| CVE | Year | Component | Type | CVSS | Status |
|-----|------|-----------|------|------|--------|
| CVE-2025-55182 | 2025 | React Server Components | Prototype pollution + RCE | 10.0 | Exploited ITW |
| CVE-2025-6558 | 2025 | V8 JIT | Memory corruption | Critical | Exploited ITW |
| CVE-2025-6554 | 2025 | V8 JIT | Type confusion | Critical | Exploited ITW |
| CVE-2025-10585 | 2025 | V8/Wasm | Type confusion | Critical | Exploited ITW |
| CVE-2025-12735 | 2025 | expr-eval | eval RCE | 9.8 | Public PoC |
| CVE-2024-5830 | 2024 | V8 | Type confusion | Critical | Exploited |
| CVE-2024-21529 | 2024 | dset | Prototype pollution | High | Public |
| CVE-2024-21505 | 2024 | web3-utils | Prototype pollution | High | Public |
| CVE-2024-4367 | 2024 | PDF.js | Arbitrary JS execution | High | Public PoC |
| CVE-2023-6699 | 2023 | V8 Wasm | Sandbox escape | High | Public PoC |
| CVE-2022-31129 | 2022 | moment.js | ReDoS | Moderate | Public |
| CVE-2020-28500 | 2020 | lodash | ReDoS | High | Public |
| CVE-2019-9810 | 2019 | SpiderMonkey | Bounds check opt | Critical | Public PoC |

---

## Language Design Critique

**Structural issues** (1990s decisions): Dynamic typing + implicit coercion, `__proto__`/`with`/`var` hoisting for backward compatibility, global prototype chain as pollution surface, `eval()`/`Function()` by design.

**Modern improvements**: Strict mode (ES5), `let`/`const` (ES6), `Map`/`Set` (ES6), `Object.create(null)`/`Object.freeze` (ES5), `Symbol` (ES6), private fields `#field` (ES2022), TypeScript for compile-time type safety.

**Secure runtimes**: Deno (permission model, secure-by-default), Bun (performance focus, less mature security).

---

## Sources

**Specs**: [ECMA-262](https://tc39.es/ecma262/)

**Prototype Pollution**: [MDN](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution) | [CVE-2025-55182 Datadog](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/) | [PortSwigger](https://portswigger.net/web-security/prototype-pollution)

**V8/Engines**: [Chrome V8 Zero-Day Analysis](https://www.rescana.com/post/chrome-may-2025-emergency-update-in-depth-analysis-of-the-fifth-zero-day-vulnerability-in-the-v8-en) | [JIT Vulnerabilities](https://trustfoundry.net/2025/01/14/a-mere-mortals-introduction-to-jit-vulnerabilities-in-javascript-engines/) | [V8 Sandbox](https://v8.dev/blog/sandbox) | [V8 Untrusted Code Mitigations](https://v8.dev/docs/untrusted-code-mitigations)

**eval/RCE**: [CVE-2025-12735 expr-eval](https://www.techzine.eu/news/security/136255/critical-vulnerability-exposed-in-javascript-library-expr-eval/) | [GitHub RCE in Chrome JIT](https://github.blog/security/vulnerability-research/getting-rce-in-chrome-with-incorrect-side-effect-in-the-jit-compiler/)

**ReDoS**: [OWASP](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS) | [Snyk](https://learn.snyk.io/lesson/redos/)

**Wasm**: [CVE-2023-6699](https://www.ameeba.com/blog/cve-2023-6699-sandbox-escape-vulnerability-in-webassembly-wasm-in-v8-javascript-engine/) | [V8 Sandbox Escape Technique](https://theori.io/blog/a-deep-dive-into-v8-sandbox-escape-technique-used-in-in-the-wild-exploit)
