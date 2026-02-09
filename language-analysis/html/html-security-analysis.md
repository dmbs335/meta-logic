# HTML Security Analysis

> **Analysis Target**: WHATWG HTML Living Standard, Browser Parser Implementations (Blink, Gecko, WebKit)
> **Methodology**: Spec extraction + browser parser differential analysis + attack vector mapping
> **Latest Cases**: CVE-2024-45801 (DOMPurify mXSS), CVE-2024-47875 (DOMPurify clobbering), CVE-2020-6812 (Firefox NULL byte)
> **Date**: February 2026

---

## Executive Summary

HTML security issues stem from **parser complexity** (80+ tokenizer states) and **specification ambiguity**. Core attack surfaces: (1) **Mutation XSS (mXSS)** — DOM mutation during serialization/reparsing bypasses sanitization, (2) **DOM Clobbering** — spec-defined `id`/`name` attribute overwriting of `window`/`document` properties, (3) **namespace confusion** at SVG/MathML integration points, (4) **parser differentials** between sanitizer and browser implementations, (5) **innerHTML misconceptions** — event handlers and SVG scripts execute despite spec claiming "no security implications." 5 attack classes mapped to spec sections.

---

## Part I: Specification Analysis

### 1. Tokenization State Machine (WHATWG §13.2.5)

80+ states with security-critical ambiguities. **NULL byte**: spec says emit U+FFFD replacement, but Blink treats as string terminator, Gecko replaces, WebKit is context-dependent → CVE-2020-6812 (Firefox NULL byte XSS filter bypass). **EOF in script data**: whether incomplete script tags execute is unclear → root cause for mXSS.

### 2. Tree Construction and Foster Parenting (WHATWG §13.2.6)

23 insertion modes. Foster parenting moves improper content outside tables → `<table><script>alert(1)</script></table>` may execute before table construction.

### 3. Foreign Content Integration Points (WHATWG §13.2.6.5)

SVG/MathML parsing rules switch when embedded in HTML. Attribute handling unclear across namespaces. SVG `<script href="...">` differs from HTML `<script src="...">`. `<foreignObject>` and `<annotation-xml encoding="text/html">` create HTML integration points where HTML parsing resumes.

### 4. innerHTML Security Boundary (WHATWG §8.2)

Spec §8.2.1 claims "no security implications beyond allowing arbitrary content." **Misleading**: `<script>` doesn't execute, but event handlers (`onerror`, `onload`), SVG scripts, and DOM Clobbering all activate via innerHTML.

### 5. Event Handler Attributes (WHATWG §6.1.7.2)

Spec provides no guidance on which event handlers should be restricted in sanitization. Commonly abused: `<img src=x onerror=...>`, `<svg onload=...>`, `<input onfocus=... autofocus>`, `<details ontoggle=... open>`, `<marquee onstart=...>`.

### 6. Other Ambiguities

**Comments**: conditional/nested comment handling varies across browsers. **CDATA**: valid only in SVG/MathML but some parsers accept in HTML context → sanitizer bypass. **Character encoding**: BOM → HTTP → meta charset priority ambiguity enables encoding confusion. **Form reassociation** (§4.10.3): `form` attribute allows association regardless of tree position → DOM Clobbering basis.

---

## Part II: Browser Parser Differentials

### 7. Blink (Chrome/Edge)

Preload scanner discovers resources ahead of main parser → timing differentials. Foster parenting edge cases with foreign content + nested tables differ from spec.

### 8. Gecko (Firefox)

CVE-2020-6812: URL parser treated `%00` as string terminator while HTML parser continued. SVG/MathML namespace handling stricter — `<style>` treatment differs between SVG and HTML context.

### 9. WebKit (Safari)

Unique quirks mode behavior. Template element `<template>` script execution differs across browsers when content cloned and appended.

### 10. Quirks Mode Impact

Missing/legacy DOCTYPE triggers quirks mode → relaxed CSS parsing (IE `expression()`), form encoding differences, hash fragment navigation variations → historical XSS vectors.

---

## Part III: Attack Techniques

### 11. Mutation XSS (mXSS)

DOM mutates during serialization→reparsing, bypassing sanitization. Sanitizer parses → serializes via innerHTML → browser reparses with shifted tag boundaries.

**Patterns**: `<noscript>` — sanitizer sees inert content, reparsing closes tag and exposes payload. `<style><style></style><script>alert(1)` — nested style confusion. SVG/MathML foreign content mutations via `<annotation-xml encoding="text/html">`.

### 12. DOM Clobbering (WHATWG §7.3.3)

Spec-defined behavior: `id`/`name` attributes overwrite `window`/`document` properties. **Nested**: `<form id="config"><input name="apiUrl" value="http://evil.com">` → `config.apiUrl` returns input element, converts to string in `fetch()`. **HTMLCollection**: duplicate IDs create collections.

**Real-world**: Google reCAPTCHA bypass (2019) — clobbered `g-recaptcha-response`. DOMPurify bypass (CVE-2020-26870) — clobbered sanitization config. CDN takeover via clobbered fallback URL.

### 13. Namespace Confusion (SVG/MathML)

SVG XSS: `<svg onload=...>`, `<svg><script>`, `<svg><animate onbegin=...>`, `<svg><foreignObject><body onload=...>`. MathML XSS: `<math><mtext><script>`, `<math><annotation-xml encoding="text/html"><script>`.

### 14. Parser Differential Attacks

Comment differential: `<!--><script>alert(1)</script><!----->` — DOMPurify sees comment, browser executes. Attribute parsing: `/` between attributes creates inconsistencies. Case variation, whitespace injection, entity encoding — all create sanitizer/browser disagreements.

### 15. Other Vectors

**Prototype pollution via forms**: `<input name="__proto__">` + `<input name="isAdmin" value="true">` → iterate form elements into object → pollutes Object.prototype. **Data URI**: `<iframe src="data:text/html,...">`. **Meta injection**: `<meta http-equiv="refresh" content="0;url=javascript:...">`. **CSS injection**: attribute selectors exfiltrate input values character-by-character.

---

## Part IV: DOMPurify Bypass Case Studies

| CVE | Year | Technique | Fix |
|-----|------|-----------|-----|
| CVE-2024-45801 | 2024 | MathML/SVG nested mXSS | DOMPurify 3.1.7 |
| CVE-2024-47875 | 2024 | Config override via DOM Clobbering | DOMPurify 3.1.8 (frozen config) |
| CVE-2020-26870 | 2020 | noembed/style mutation XSS | DOMPurify 2.2.1 |
| CVE-2019-20374 | 2019 | Foreign content mXSS | DOMPurify 2.0.8 |
| CVE-2019-16728 | 2019 | Template/form clobbering | DOMPurify 2.0.1 |

Most bypasses converge on three patterns: (1) foreign content integration points, (2) serialization/reparsing mutation, (3) DOM Clobbering.

---

## Part V: Browser Security Features

### 16. Trusted Types API

Prevents DOM XSS by requiring typed values for dangerous sinks (`innerHTML`, `eval`, `setTimeout(string)`). CSP: `require-trusted-types-for 'script'`. Support: Chrome/Edge 83+. Firefox: under consideration. Safari: not supported.

### 17. HTML Sanitizer API (W3C Draft)

Browser-native sanitization — parser-aware, structurally eliminates mXSS. Chrome Origin Trial (105+). Firefox/Safari: in development.

### 18. CSP Bypass Patterns

JSONP endpoint on trusted domain, base tag injection (missing `base-uri`), AngularJS template injection, `strict-dynamic` propagation to child scripts.

**Recommended**: `script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script'`.

### 19. document.domain Deprecation

Relaxed same-origin policy across subdomains — deprecated. Chrome 109+ (2023), Firefox 103+ (2022) disabled by default. Replacement: `postMessage()`, `Origin-Agent-Cluster: ?1`.

---

## Attack-Spec-Defense Mapping

| Attack | Spec Reference | Defense |
|--------|---------------|---------|
| Mutation XSS | §13.2.6 (tree construction) | Trusted Types, Sanitizer API, latest DOMPurify |
| DOM Clobbering | §7.3.3 (Named Access on Window) | Avoid bare `window.` property access, Object.freeze |
| Namespace confusion | §13.2.6.5 (foreign content) | Strip foreign content or allowlist sanitization |
| innerHTML XSS | §8.2, §6.1.7.2 (event handlers) | Trusted Types, minimize innerHTML |
| Parser differential | §13.2.5 (tokenization) | Browser-native Sanitizer API |
| CSS injection | CSS Selectors L4 | CSP `style-src 'nonce-...'` |
| Data URI XSS | §4.8.5 (iframe src) | CSP `frame-src`, block `data:` |
| Template injection | §4.12.1 (script execution) | Context-aware output encoding |
| Prototype pollution | §4.10 (form elements) | `Object.create(null)`, `Map`, input validation |
| Encoding bypass | §4.2.5 (charset detection) | Explicit `charset=UTF-8`, `X-Content-Type-Options: nosniff` |

---

## Sources

**Specs**: [WHATWG HTML Living Standard](https://html.spec.whatwg.org/) | [W3C Trusted Types](https://w3c.github.io/trusted-types/dist/spec/) | [W3C Sanitizer API](https://wicg.github.io/sanitizer-api/) | [W3C CSP Level 3](https://www.w3.org/TR/CSP3/)

**Research**: [PortSwigger Web Security Research](https://portswigger.net/research) | [Cure53 (DOMPurify)](https://cure53.de/#publications) | [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | [HTML5 Security Cheatsheet](https://html5sec.org/)

**Academic**: Mario Heiderich et al., "mXSS Attacks" (2013) | Sebastian Lekies et al., "Script Gadgets" (2017)
