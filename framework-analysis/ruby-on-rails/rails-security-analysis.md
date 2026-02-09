# Ruby on Rails Security Analysis: Meta-Structural Direct Extraction

> **Analysis Target**: Ruby on Rails (versions 5.2.0 - 8.0.x)
> **Sources**: [rails/rails GitHub](https://github.com/rails/rails), [Rails Security Guide](https://guides.rubyonrails.org/security.html)
> **Date**: February 2026
> **CVE Coverage**: CVE-2025-24293, CVE-2023-22797, CVE-2022-32224, CVE-2015-7576

---

## Executive Summary

Rails' "Convention over Configuration" philosophy prioritizes developer productivity through implicit behaviors. This analysis extracts **16 meta-patterns** where framework automation obscures security boundaries, creating structural vulnerabilities. Key findings: (1) mass assignment retrofitted with Strong Parameters in Rails 4, (2) YAML/Marshal deserialization enabling RCE, (3) `method_missing` and reflection creating unsafe code paths, (4) ERB template injection surfaces, (5) development-to-production configuration gaps.

---

## Part 1: Framework Design Philosophy

### 1. Convention over Configuration → Hidden Security Decisions

Rails minimizes configuration by establishing conventions—autoloading maps file paths to classes, auto-routing maps controllers to endpoints, and parameter auto-binding maps HTTP params to attributes.

**Security Problem**: Conventions obscure trust boundaries. Developers don't explicitly declare which parameters are trusted, adding files can create public endpoints, and "magic" makes runtime behavior non-obvious.

**Attack Vector — `constantize` Exploitation**:
```ruby
# VULNERABLE: User controls class instantiation
strategy = params[:strategy].constantize.new
# Attack: ?strategy=Logger → Logger.new with attacker-controlled filename → command injection

# SECURE: Explicit allowlist
ALLOWED = { 'daily' => DailySummaryStrategy, 'weekly' => WeeklySummaryStrategy }.freeze
strategy_class = ALLOWED[params[:strategy]] or raise "Invalid"
```

**CVEs**: CVE-2013-0156 (auto-parsing XML/YAML/JSON enabled arbitrary object instantiation). Research: [Praetorian Ruby Unsafe Reflection](https://www.praetorian.com/blog/ruby-unsafe-reflection-vulnerabilities/)

---

### 2. Mass Assignment — The 2012 GitHub Breach

Before Rails 4, `ActiveRecord::Base` automatically mapped all columns as assignable. `Model.new(params)` accepted any hash keys with no protection.

**Attack**: `POST { user: { email: "evil@x.com", is_admin: true } }` → attacker creates admin account.

**2012 GitHub Breach**: Attacker exploited mass assignment to add SSH key to Rails org, gaining write access to any repo. This forced Rails 4's Strong Parameters retrofit.

**Strong Parameters** ([source](https://github.com/rails/rails/blob/main/actionpack/lib/action_controller/metal/strong_parameters.rb)):
```ruby
# Parameters default to unpermitted (permitted = false)
# Explicit allowlist required:
def user_params
  params.require(:user).permit(:email, :password)  # is_admin excluded
end
```

**Rules**: Always use `.permit()` with explicit list. Never use `.permit!`. Audit params when adding columns. Use Brakeman for static analysis.

---

### 3. Implicit Deserialization → YAML/Marshal RCE

Rails serializes objects via `Marshal` and `YAML.load()` for database storage, sessions, and cookies. Both formats include **type metadata** enabling arbitrary class instantiation during deserialization.

**Gadget chains** (via [ysoserial-like payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md)) use standard Ruby classes (`Gem::*`, `Net::*`) to achieve RCE without application-specific code.

| CVE | Year | Impact | Component |
|-----|------|--------|-----------|
| CVE-2013-0156 | 2013 | RCE | XML/YAML parameter parsing |
| CVE-2022-32224 | 2022 | RCE | Serialized columns in ActiveRecord |
| CVE-2021-22880 | 2021 | DoS | PostgreSQL YAML deserialization |

**Rails treated serialization as internal implementation, not a trust boundary** — assuming session cookies are tamper-proof, DB content is trusted, and serialization is "just storage."

**Mitigation**: Since Rails 7.1, `YAML.safe_load` is default. Best practice: avoid object serialization entirely — use JSON:
```ruby
class User < ApplicationRecord
  store :preferences, accessors: [:theme, :language], coder: JSON
end
```

---

### 4. Development Mode in Production → Information Disclosure

Development mode exposes stack traces, environment variables, source code, request params, and session data via `ActionDispatch::DebugExceptions`.

**Additional risks**: `web-console` gem (RCE via browser REPL), verbose logging (passwords/tokens), `better_errors` gem (live REPL).

**Secure production settings**:
```ruby
config.consider_all_requests_local = false
config.log_level = :info
config.force_ssl = true  # Rails 7.1+ default
Rails.application.config.filter_parameters += [
  :password, :api_key, :access_token, :secret, :private_key, :ssn, :credit_card
]
```

---

### 5. SQL Injection via String Interpolation

ActiveRecord makes SQL injection easy to avoid AND easy to introduce:

```ruby
# VULNERABLE: String interpolation (no escaping)
User.where("username = '#{params[:username]}'")

# SECURE: Placeholder or hash
User.where("username = ?", params[:username])
User.where(username: params[:username])
```

**Common pitfalls**: Dynamic `ORDER BY` via interpolation, `find_by_sql` bypassing escaping, complex conditions built as strings.

**Secure patterns**:
```ruby
# ORDER BY: allowlist
ALLOWED_SORT = ['created_at', 'email'].freeze
User.order(ALLOWED_SORT.include?(params[:sort]) ? params[:sort] : 'created_at')

# LIKE: escape wildcards
User.where("email LIKE ?", "%#{ActiveRecord::Base.sanitize_sql_like(params[:q])}%")
```

---

### 6. XSS via `html_safe` and Raw Rendering

Rails 3+ auto-escapes ERB `<%= %>` output. However, `html_safe` (confusingly named — it removes protection, not adds it), `raw()`, and `<%== %>` bypass escaping.

```ruby
# VULNERABLE: Marking user input as safe
@greeting = "Hello, #{params[:name]}".html_safe  # XSS!

# SECURE: Escape user input first
escaped = ERB::Util.html_escape(params[:name])
@greeting = "Hello, <strong>#{escaped}</strong>".html_safe
```

**Additional risks**: `sanitize()` helper has had multiple CVEs (CVE-2022-32209 XSS bypass). Defense-in-depth: use CSP to block inline scripts. Prefer Markdown over raw HTML for user content.

---

## Part 2: Source Code Level Vulnerable Structures

### 7. Server-Side Template Injection (SSTI)

ERB templates have **full Ruby execution** with no sandbox. User input reaching `render inline:` enables RCE:

```ruby
# VULNERABLE
render inline: "Hello #{params[:name]}"
# Attack: ?name=<%= system('cat /etc/passwd') %>

# SECURE: Predefined template allowlist
TEMPLATES = { 'daily' => 'reports/daily', 'weekly' => 'reports/weekly' }.freeze
render template: TEMPLATES[params[:template]] || 'reports/default'
```

Unlike Django/Jinja2 (sandboxed templates), Rails treats templates as Ruby code. Sources: [TrustedSec](https://trustedsec.com/blog/rubyerb-template-injection), [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection)

---

### 8. Unsafe Reflection and Dynamic Method Invocation

Ruby's `send`, `constantize`, `method_missing`, `const_get` allow metaprogramming but create attack surfaces when user input controls method/class names:

```ruby
# VULNERABLE: send with user input
send(params[:action])  # User controls which method runs

# VULNERABLE: constantize
params[:type].constantize.new(params[:config])
# Attack: ?type=Logger&config[filename]=|cat /etc/passwd

# SECURE: Factory pattern with allowlist
HANDLERS = { 'csv' => CsvHandler, 'json' => JsonHandler }.freeze
HANDLERS[type]&.new or raise "Invalid"
```

CVEs: CVE-2013-0156, CVE-2019-5420. [Praetorian research](https://www.praetorian.com/blog/ruby-unsafe-reflection-vulnerabilities/) demonstrated Logger gadget exploitation.

---

### 9. CSRF Protection Complexity

Rails includes CSRF via `protect_from_forgery` (authenticity token validation on non-GET requests). Common misconfigurations:

- `skip_before_action :verify_authenticity_token` on cookie-authenticated API endpoints
- `:null_session` strategy resets session instead of raising exception
- Hybrid apps mixing HTML (needs CSRF) and API (token-based, doesn't need CSRF)

**Secure pattern**: Separate base controllers:
```ruby
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception  # HTML
end
class Api::BaseController < ActionController::API  # No session/CSRF
end
```

---

### 10. Open Redirect Vulnerabilities

`redirect_to` accepts any URL. Before Rails 7.0, no validation was enforced.

**CVE-2023-22797**: Crafted `Host` headers bypassed `allowed_hosts` → open redirect. [Invicti](https://www.invicti.com/web-application-vulnerabilities/ruby-on-rails-url-redirection-to-untrusted-site-open-redirect-vulnerability-cve-2023-22797)

**Rails 7.0+ protection**:
```ruby
config.action_controller.raise_on_open_redirects = true
redirect_to params[:url], allow_other_host: true  # Explicit opt-in
```

Best practice: Use path-only redirects or store targets server-side (`session[:return_to]`).

---

### 11. Timing Attacks on Authentication

Ruby's `==` returns on first mismatch, creating measurable timing differences.

**CVE-2015-7576**: `http_basic_authenticate_with` used non-constant-time comparison.

**Fix**: Use `ActiveSupport::SecurityUtils.secure_compare(expected, provided)`. Note: even `secure_compare` leaks string **length**. Combine with rate limiting (`Rack::Attack`).

---

## Part 3: Language-Level Design Issues

### 12. Symbol DoS (Historical, Ruby < 2.2)

Pre-Ruby 2.2, Symbols were never garbage collected. User-controlled `to_sym` created unlimited Symbols → OOM. CVEs: CVE-2013-1854, CVE-2013-1855. **Resolved**: Ruby 2.2+ has Symbol GC. Modern Rails targets Ruby 2.7+.

---

### 13. File Upload and ActiveStorage RCE (CVE-2025-24293)

**CVE-2025-24293** (Critical, Jan 2025): ActiveStorage's default allowed transformation methods (`loader`, `saver`, `apply`) passed to ImageMagick without input validation → command injection RCE.

**Exploit chain**: Upload image → request variant with `?t=loader&v=;cat /etc/passwd` → ImageMagick executes shell command. Fixed in 7.1.5.2, 7.2.2.2, 8.0.2.1+. Source: [OPSWAT](https://www.opswat.com/blog/critical-cve-2025-24293-in-ruby-on-rails-active-storage-rce-discovered-by-opswat-unit-515)

**Mitigation**: Never accept user-controlled transformation methods. Use predefined variants only. Validate file types by content (magic bytes), not extension. Restrict ImageMagick via `policy.xml`.

---

### 14. Session and Cookie Security

Rails stores session data in encrypted cookies. Security depends entirely on `secret_key_base` secrecy — if leaked, attacker can decrypt sessions, forge cookies, and inject serialized objects.

**Leakage vectors**: Committed to git, environment variable exposure, development secrets in production.

**Secure configuration**:
```ruby
Rails.application.config.session_store :cookie_store,
  key: '_app_session', secure: Rails.env.production?,
  httponly: true, same_site: :lax, expire_after: 30.minutes
```

For higher security, use Redis/DB-backed sessions. Protect `secret_key_base` via `rails credentials:edit` (never commit `config/master.key`).

---

### 15. Dependency Supply Chain Security

Rails apps depend on 100+ gems. Attack surfaces: compromised maintainer accounts, typosquatting (`devise-auth` vs `devise`), dependency confusion, malicious transitive dependencies.

**Real incidents**: `strong_password` gem compromised (2019), `rest-client` typosquat (2021).

**Mitigation**: Pin exact versions. Use `bundler-audit` in CI/CD. Use private gem server for internal gems. Review `Gemfile.lock` diffs. Use Dependabot/Snyk for monitoring.

---

### 16. Insecure Defaults and Configuration Gaps

Multiple production-insecure defaults:

| Default | Risk | Fix |
|---------|------|-----|
| Only `:password` filtered in logs | API keys, tokens leaked | Add all sensitive params |
| No CSP configured | XSS exploitation unrestricted | Configure CSP with nonce |
| No CORS configured (or `origins '*'`) | Cross-site API abuse | Whitelist specific origins |
| Missing security headers | Various | Use `secure_headers` gem |
| `force_ssl = false` (pre-7.1) | MITM | Set `force_ssl = true` |

**Production hardening**:
```ruby
config.force_ssl = true
config.log_level = :info
config.consider_all_requests_local = false
config.action_controller.raise_on_open_redirects = true
config.action_dispatch.default_headers = {
  'X-Frame-Options' => 'DENY', 'X-Content-Type-Options' => 'nosniff',
  'Referrer-Policy' => 'strict-origin-when-cross-origin'
}
```

---

## Part 4: CVE Summary (2023-2025)

| CVE | Year | Severity | Root Cause | Meta-Pattern |
|-----|------|----------|------------|--------------|
| CVE-2025-24293 | 2025 | Critical | ActiveStorage transformation → ImageMagick RCE | #13: File Upload |
| CVE-2023-22797 | 2023 | High | Open redirect via Host headers | #10: Open Redirect |
| CVE-2022-32224 | 2022 | Critical | YAML deserialization RCE in serialized columns | #3: Deserialization |
| CVE-2022-32209 | 2022 | Medium | XSS in rails-html-sanitizer parser differential | #6: XSS |
| CVE-2021-22880 | 2021 | High | PostgreSQL YAML deserialization DoS | #3: Deserialization |
| CVE-2015-7576 | 2015 | Medium | Timing attack in http_basic_authenticate_with | #11: Timing |
| CVE-2013-0156 | 2013 | Critical | YAML/XML RCE via parameter parsing | #3: Deserialization |

---

## Appendix A: Meta-Pattern ↔ Attack ↔ Defense Mapping

| Pattern | Attack | Mitigation |
|---------|--------|------------|
| #1 Convention | `constantize` → arbitrary class | Explicit allowlist |
| #2 Mass Assignment | `is_admin=true` in POST | Strong Parameters `.permit()` |
| #3 Deserialization | YAML gadget chains → RCE | `YAML.safe_load` or JSON |
| #4 Dev Mode | Error pages leak secrets | `consider_all_requests_local = false` |
| #5 SQL Injection | String interpolation in `where()` | Placeholders `?` or hash conditions |
| #6 XSS | `html_safe` on user input | Never `html_safe` untrusted data |
| #7 SSTI | ERB injection via `render inline:` | Predefined template allowlist |
| #8 Reflection | `send`/`constantize` with user input | Allowlist methods/classes |
| #9 CSRF | Skip CSRF on cookie-auth API | Separate API/HTML controllers |
| #10 Open Redirect | `redirect_to params[:url]` | `raise_on_open_redirects = true` |
| #11 Timing | Non-constant-time `==` | `secure_compare` + rate limiting |
| #12 Symbol DoS | Unlimited `to_sym` (historical) | Ruby 2.2+ Symbol GC |
| #13 File Upload | ActiveStorage → ImageMagick RCE | Predefined variants only |
| #14 Session | Leaked `secret_key_base` → forgery | Encrypted credentials, Redis sessions |
| #15 Supply Chain | Typosquat/compromised gems | `bundler-audit`, pin versions |
| #16 Insecure Defaults | Missing CSP, headers, SSL | Explicit production hardening |

---

## Appendix D: Framework Version Security Changes

| Version | Security Change | Breaking? |
|---------|----------------|-----------|
| Rails 7.1 | `force_ssl = true` default | No |
| Rails 7.0 | Open redirect protection | Yes |
| Rails 6.1 | Stricter CSP support | No |
| Rails 5.2 | Encrypted credentials, ActiveStorage | No |
| Rails 4.2 | Cookies encrypted by default | No |
| Rails 4.0 | Strong Parameters mandatory | Yes |
| Rails 3.0 | XSS auto-escape in ERB | Yes |

---

## Conclusion

Rails' "Convention over Configuration" creates a **productivity-security paradox**: implicit behaviors that accelerate development obscure security boundaries. The 2012 GitHub breach (mass assignment), CVE-2013-0156 (YAML RCE), and CVE-2025-24293 (ActiveStorage RCE) demonstrate that Rails security issues stem from **architectural trade-offs favoring flexibility over safety**. The framework retrofits security (Strong Parameters in Rails 4, open redirect protection in Rails 7) rather than designing with security-first principles.

Secure Rails applications require: (1) explicit allowlisting everywhere, (2) rejecting dangerous defaults, (3) defense-in-depth (CSP, headers, rate limiting), (4) continuous monitoring (bundler-audit, Brakeman).

---

## References

- [Rails Security Guide](https://guides.rubyonrails.org/security.html) | [Rails GitHub](https://github.com/rails/rails) | [OWASP Rails Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html)
- [Brakeman](https://brakemanscanner.org/) | [bundler-audit](https://github.com/rubysec/bundler-audit) | [Semgrep Rails XSS](https://semgrep.dev/docs/cheat-sheets/rails-xss)
- [CVE-2025-24293 OPSWAT](https://www.opswat.com/blog/critical-cve-2025-24293-in-ruby-on-rails-active-storage-rce-discovered-by-opswat-unit-515) | [CVE-2022-32224](https://discuss.rubyonrails.org/t/cve-2022-32224-possible-rce-escalation-bug-with-serialized-columns-in-active-record/81017)
- [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection) | [Praetorian Unsafe Reflection](https://www.praetorian.com/blog/ruby-unsafe-reflection-vulnerabilities/)
- [Rails Security Checklist](https://github.com/brunofacca/zen-rails-security-checklist) | [PayloadsAllTheThings Ruby Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md)
