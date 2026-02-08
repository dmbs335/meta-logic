# DNS Security Analysis: Direct Extraction from RFC Specifications

> **Analysis Target**: RFC 1035 (DNS Core), RFC 4033/4034 (DNSSEC), RFC 5452 (Cache Poisoning), RFC 7858 (DoT), RFC 8484 (DoH), RFC 9460 (SVCB/HTTPS RR), RFC 7816 (QNAME Minimisation), RFC 8490 (DSO), RFC 9210 (XoT)
>
> **Methodology**: Security considerations extracted directly from RFC specifications, cross-referenced with recent CVEs (2024-2025), academic research, and real-world attack campaigns
>
> **Latest Cases Reflected**: KeyTrap (CVE-2023-50387/50868), DoH vulnerabilities (CVE-2024-12705), DNS amplification attacks, SubdoMailing campaign, and 2024 threat landscape data

---

## Part I: Core DNS Protocol Architecture and Foundational Security Gaps

### 1. The Original Sin: RFC 1035's Security Vacuum (RFC 1035)

**Specification Behavior**: RFC 1035, published in 1987, contains **no dedicated Security Considerations section**. The specification mandates case-insensitive string comparisons and basic message validation but provides no guidance on authentication, integrity, or confidentiality.

**Security Implications**: This fundamental gap created decades of security debt. The protocol assumes a benign network where all participants are trustworthy—an assumption that never reflected reality and became catastrophically obsolete with the adversarial Internet.

**Attack Vectors**: The absence of security design enabled an entire taxonomy of attacks:
- **Cache poisoning**: No response authentication allows injection of false records
- **Man-in-the-middle attacks**: No encryption permits interception and modification
- **Zone enumeration**: No access controls expose internal network topology
- **Amplification DDoS**: No source validation enables reflection attacks

**Real-World Cases**:
- [Kaminsky vulnerability (2008)](https://en.wikipedia.org/wiki/DNS_spoofing) exploited RFC 1035's weak query ID randomization
- [KeyTrap (CVE-2023-50387)](https://www.akamai.com/blog/security/dns-exploit-keytrap-posed-major-internet-threat) demonstrated DNSSEC's attempt to patch these gaps introduced new DoS vectors

**Spec-Based Defense**: RFC 1035 provides none. All modern defenses (DNSSEC, DoT, DoH, query ID randomization) were retrofitted in subsequent RFCs to address the original protocol's security vacuum.

---

### 2. Query ID Entropy: The 16-Bit Weakness (RFC 1035 §4.1.1, RFC 5452 §7.2)

**Specification Behavior**: RFC 1035 specifies that query IDs "can be used by the requester to match up replies to outstanding queries" but doesn't mandate randomization. RFC 5452 later mandates: *"MUST use an unpredictable query ID for outgoing queries, utilizing the full range available (0-65535)."*

**Security Implications**: Only 16 bits of entropy (65,536 possibilities) creates a race condition window exploitable by attackers who can flood resolvers with spoofed responses.

**Attack Vectors**:
```
1. Attacker triggers resolver to query attacker.example.com
2. Resolver sends query with ID X to authoritative nameserver
3. Attacker floods resolver with spoofed responses:
   - ID 0 → malicious IP
   - ID 1 → malicious IP
   - ...
   - ID 65535 → malicious IP
4. If spoofed response with ID X arrives before legitimate response,
   cache is poisoned
```

The [Kaminsky attack (2008)](https://en.wikipedia.org/wiki/DNS_spoofing) demonstrated systematic exploitation by querying random subdomains to bypass cache and repeatedly attempting poisoning.

**Real-World Cases**:
- Dan Kaminsky's research revealed that 16-bit IDs combined with predictable source ports created a practical attack window measured in seconds
- [Cache poisoning remains viable](https://www.usenix.org/system/files/usenixsecurity25-afek.pdf) when combined with other weaknesses (predictable ports, IP fragmentation)

**Spec-Based Defense**: RFC 5452 mandates combining multiple entropy sources:
- *"MUST use an unpredictable source port for outgoing queries"* (adds ~16 bits)
- Query ID randomization (16 bits)
- Combined ~32 bits makes brute force attacks impractical

---

### 3. Source Port Randomization: Essential Entropy Amplification (RFC 5452 §7.1)

**Specification Behavior**: RFC 5452 mandates: *"MUST use an unpredictable source port for outgoing queries from the range of available ports (53, or 1024 and above) that is as large as possible and practicable."* Additionally: *"MUST use multiple different source ports simultaneously in case of multiple outstanding queries."*

**Security Implications**: Source port randomization adds approximately 16 bits of additional entropy beyond query IDs, creating a ~32-bit search space (2^32 = 4.3 billion combinations) that makes blind spoofing attacks computationally infeasible.

**Attack Vectors**: Implementations that violate this requirement remain vulnerable:
- **Fixed source port 53**: Attacker only needs to guess 16-bit query ID
- **Sequential port allocation**: Attacker can predict next port from observed queries
- **Limited port range**: NAT devices or firewalls restricting ports reduce entropy

**Real-World Cases**:
- [Pre-2008 resolvers](https://www.cs.cornell.edu/~shmat/shmat_securecomm10.pdf) commonly used fixed source ports, enabling cache poisoning with ~100-1000 spoofed responses
- DNS forwarders and NAT devices often destroy port randomization, creating [persistent vulnerability points](https://www.infoblox.com/dns-security-resource-center/what-are-dns-spoofing-dns-hijacking-dns-cache-poisoning/)

**Spec-Based Defense**:
- Use cryptographic random number generators per RFC 4086
- Avoid port exclusions unless absolutely necessary
- Implement TCP fallback when spoofing detected (RFC 5452 §9.2)

---

### 4. Response Validation: The Six-Tuple Match (RFC 5452 §7)

**Specification Behavior**: RFC 5452 mandates: *"Resolvers MUST match responses to all of the following attributes of the query: Source address against query destination address; Destination address against query source address; Destination port against query source port; Query ID; Query name; Query class and type."*

**Security Implications**: This six-tuple validation creates multiple independent checks an attacker must bypass simultaneously. Failure to validate any single attribute opens attack vectors.

**Attack Vectors**: Implementation shortcuts create vulnerabilities:

| Omitted Check | Attack Enabled |
|---------------|----------------|
| Source address | Off-path attacker can spoof from any IP |
| Destination port | Attacker can spray responses to multiple ports |
| Query name | Cross-query cache poisoning (poison A while querying B) |
| Query class/type | Type confusion attacks (inject CNAME as A record) |

**Real-World Cases**:
- Some early resolvers only checked query ID, enabling trivial cache poisoning
- [IP fragmentation attacks](https://www.usenix.org/system/files/usenixsecurity25-afek.pdf) bypass source address validation by injecting malicious fragments that reassemble with legitimate responses

**Spec-Based Defense**: Strict validation in order of specificity:
```
1. Network layer: Source/destination IP and port
2. DNS layer: Query ID
3. Semantic layer: Query name, class, type match
4. Authority layer: Bailiwick checking (response within queried domain)
```

---

### 5. TTL Handling: Caching as a Double-Edged Sword (RFC 1035 §3.2.1, §4.1.3)

**Specification Behavior**: RFC 1035 mandates: *"Zero values are interpreted to mean that the RR can only be used for the transaction in progress, and should not be cached."* The MINIMUM field in SOA records *"functions as a lower bound on the TTL field for all RRs in a zone."*

**Security Implications**: TTL values control both performance (cache hit rates) and security (how long poisoned records persist). Attackers manipulating TTL can extend persistence of malicious records or force excessive resolver load.

**Attack Vectors**:
- **Short TTL abuse**: Setting TTL=0 or very low values forces resolvers to query authoritative servers repeatedly, enabling DNS water torture attacks
- **Long TTL poisoning**: Injecting records with high TTL (days/weeks) makes poisoning persist even after attack detection
- **TTL manipulation for tracking**: Varying TTL per user enables DNS-based user tracking

**Real-World Cases**:
- [8.74% of measured resolvers violate TTL](https://taejoong.github.io/files/publications/bhowmick-2023-dns.pdf) by extending values arbitrarily, breaking change propagation
- [44.1% of DNSSEC-validating resolvers](https://taejoong.github.io/files/publications/bhowmick-2023-dns.pdf) serve expired signatures from cache, defeating DNSSEC's temporal guarantees
- Organizations with short TTLs (5 minutes) recover faster from DNS hijacking but face higher query loads

**Spec-Based Defense**:
- Respect minimum TTL from SOA records for zone-wide consistency
- Implement maximum TTL limits to bound poisoning persistence
- During security incidents, emergency TTL reduction enables rapid IP changes
- Monitor for abnormal TTL patterns (sudden drops/spikes) as attack indicators

---

## Part II: DNSSEC – Cryptographic Integrity with Fundamental Tradeoffs

### 6. DNSSEC's Explicit Non-Goals: What It Doesn't Protect (RFC 4033 §1.4, §11)

**Specification Behavior**: RFC 4033 explicitly defines DNSSEC's limitations: *"Due to a deliberate design choice, DNSSEC does not provide confidentiality"* and lacks access controls. The specification also warns: *"DNSSEC does not protect against tampering with unsigned zone data"* at delegation points.

**Security Implications**: DNSSEC solves **authentication and integrity** but creates a false sense of comprehensive security. Three critical gaps remain:

**Gap 1 - No Confidentiality**: DNS queries and responses remain plaintext even with DNSSEC validation. Passive observers see all query traffic.

**Gap 2 - No Access Control**: DNSSEC doesn't prevent unauthorized parties from resolving internal domain names. Any resolver can query and validate any signed zone.

**Gap 3 - No DoS Protection**: RFC 4033 explicitly warns: *"DNSSEC makes DNS vulnerable to a new class of denial of service attacks based on cryptographic operations against security-aware resolvers and security-aware name servers."*

**Attack Vectors**:

1. **Zone enumeration via NSEC walking**: *"An attacker can query these NSEC RRs in sequence to obtain all the names in a zone"* (RFC 4033 §11.2)
   ```
   1. Query example.com/NSEC → Returns: example.com -> api.example.com
   2. Query api.example.com/NSEC → Returns: api.example.com -> db.example.com
   3. Query db.example.com/NSEC → Returns: db.example.com -> www.example.com
   Result: Complete zone map exposed
   ```

2. **Cryptographic DoS (KeyTrap)**: The [KeyTrap vulnerability (CVE-2023-50387)](https://www.theregister.com/2024/02/13/dnssec_vulnerability_internet/) exploits DNSSEC validation: *"Resolution of a single query can lead to CPU-intensive cryptographic calculations when a resolver attempts to verify a malicious response."*

3. **Traffic analysis despite DNSSEC**: DNSSEC validates response integrity but doesn't encrypt query names—traffic analysis reveals browsing patterns.

**Real-World Cases**:
- [NSEC3 provides hashed names](https://www.ndss-symposium.org/wp-content/uploads/2017/09/bau.pdf) but remains vulnerable to dictionary attacks with rainbow tables
- [KeyTrap affected major resolvers](https://www.akamai.com/blog/security/dns-exploit-keytrap-posed-major-internet-threat) (BIND, Unbound, Knot) with single packet causing seconds-to-minutes of CPU exhaustion
- [DNSSEC deployment remains <5% of domains](https://www.upguard.com/blog/dnssec-risk) partly due to operational complexity vs. limited security gains

**Spec-Based Defense**: Understand DNSSEC's boundaries and layer additional protections:
- **For confidentiality**: Use DoT (RFC 7858) or DoH (RFC 8484)
- **For zone enumeration**: Use NSEC3 with opt-out and high iteration counts
- **For DoS**: Implement query rate limiting and consider DNSSEC validation resource limits

---

## Part III: DNS Privacy and Encrypted Transport

### 7. DNS-over-HTTPS (DoH): Privacy vs. Network Control (RFC 8484 §8)

**Specification Behavior**: RFC 8484 provides transport security via HTTPS but explicitly separates this from data integrity: *"The HTTPS connection provides transport security...but it does not provide the response integrity of DNS data provided by DNSSEC."* Critically: *"An adversary that can control the cache used by the client can affect that client's DNS view."*

**Security Implications**: DoH creates fundamental tension between user privacy and network security controls. RFC 8484 notes: *"Filtering or inspection systems that rely on unsecured transport of DNS will not function in a DoH environment."*

**Attack Vectors**:

1. **Cache poisoning via HTTP caching**: HTTP caching mechanisms introduce manipulation vectors
2. **Tracking via HTTP metadata**: Cookies, User-Agent headers, TLS session resumption
3. **DoH server correlation**: Centralized DoH servers gain visibility into users' complete browsing patterns
4. **Firewall and parental control bypass**: DoH on port 443 indistinguishable from HTTPS web traffic

**Real-World Cases**:
- [CVE-2024-12705](https://kb.isc.org/docs/cve-2024-12705): DoH implementation suffered DoS under heavy HTTP/2 query load
- Firefox DoH deployment faced pushback from ISPs and enterprise security teams losing DNS visibility

**Spec-Based Defense**:
- Use DoH with reputable providers implementing minimal logging
- Combine DoH + DNSSEC validation for both confidentiality and integrity
- Deploy enterprise DoH resolvers with certificate pinning
- Monitor TLS SNI and certificate fields to detect DoH usage

---

## Part IV: Modern Attacks and Defenses

### 8. DNS Amplification: The UDP Spoofing Problem (RFC 1035 Architecture)

**Specification Behavior**: RFC 1035's UDP-based query/response creates inherent amplification opportunity. No specification requires source address validation.

**Security Implications**: Attackers spoof victim IP as source address in queries to open resolvers. Resolver sends large responses to victim, amplifying attack traffic 28-54x.

**Attack Vectors**:
```
1. Attacker sends queries to open recursive resolvers
   Source IP: Victim's IP (spoofed)
   Query: ANY example.com (~60 bytes)

2. Resolver sends response to victim
   Response: Large answer (~3000 bytes)

3. Amplification factor: 50x
```

[2024 data](https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/) shows attackers achieve 28-54x amplification, with some attacks exceeding 1 Tbps.

**Spec-Based Defense**:
- Implement BCP 38 (RFC 2827) source address validation
- Disable recursion for public Internet queries
- Deploy Response Rate Limiting (RRL)

---

### 9. Subdomain Takeover and Dangling DNS (Configuration Vulnerability)

**Specification Behavior**: RFC 1035 allows CNAME records pointing to external domains. No specification requires validating CNAME target accessibility.

**Security Implications**: Organizations pointing internal subdomains to external services via CNAME create takeover risk when service deleted but DNS record remains.

**Attack Vectors**:
```
# Organization configures DNS
blog.example.com. CNAME myblog.platform.com.

# Organization deletes myblog account
# DNS record remains

# Attacker registers myblog on platform.com
# Attacker now controls blog.example.com
```

**Real-World Cases**:
- [SubdoMailing campaign (2024-2025)](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover) used 8,000+ legitimate domains via subdomain takeover

**Spec-Based Defense**:
- Maintain inventory of all DNS records pointing to external services
- Implement automated monitoring for NXDOMAIN/resolution failures
- Remove DNS records before deleting external services

---

## Comprehensive Security Checklist

### Core DNS Security
- [ ] Source port randomization using cryptographic RNG (RFC 5452)
- [ ] Full 16-bit query ID randomness (RFC 5452)
- [ ] Six-tuple response validation (RFC 5452)
- [ ] Bailiwick checking for all response sections
- [ ] TTL enforcement with minimum/maximum limits

### DNSSEC Deployment
- [ ] Modern algorithms (ECDSA P-256, Ed25519) per RFC 8624
- [ ] Automated key rollover with pre-publish method
- [ ] Signature refresh at 75% of validity period
- [ ] NSEC3 with salt rotation, moderate iterations (5-10)

### Encrypted DNS
- [ ] DNS-over-TLS with strict validation (RFC 7858)
- [ ] DNS-over-HTTPS with minimal logging (RFC 8484)
- [ ] Certificate pinning in enterprise environments
- [ ] QNAME minimisation (RFC 7816)

### DoS Protection
- [ ] BCP 38 source address validation (RFC 2827)
- [ ] Response Rate Limiting on authoritative servers
- [ ] Query rate limiting per client IP
- [ ] DGA detection with ML-based analysis

### Configuration Security
- [ ] Subdomain takeover monitoring
- [ ] Dangling record scanning
- [ ] NS record change alerting
- [ ] Registry lock for critical domains
- [ ] RPZ deployment with threat intel feeds

---

## Sources and References

### RFC Specifications
- [RFC 1035 - Domain Names: Implementation](https://www.rfc-editor.org/rfc/rfc1035.html)
- [RFC 4033/4034 - DNSSEC](https://www.rfc-editor.org/rfc/rfc4033.html)
- [RFC 5452 - DNS Resilience against Forged Answers](https://www.rfc-editor.org/rfc/rfc5452.html)
- [RFC 7858 - DNS over TLS](https://www.rfc-editor.org/rfc/rfc7858.html)
- [RFC 8484 - DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc8484.html)

### Research
- [DNS Cache Poisoning Attacks (USENIX 2025)](https://www.usenix.org/system/files/usenixsecurity25-afek.pdf)
- [TTL Violations (PAM 2023)](https://taejoong.github.io/files/publications/bhowmick-2023-dns.pdf)
- [DNSSEC NSEC3 Security (NDSS)](https://www.ndss-symposium.org/wp-content/uploads/2017/09/bau.pdf)

### Threat Intelligence
- [DNS Water Torture (Keysight 2024)](https://www.keysight.com/blogs/en/tech/nwvs/2024/05/13/dns-water-torture-ddos-attacks)
- [2024 DNS Threats (Infoblox)](https://www.infoblox.com/blog/threat-intelligence/2024-dns-threat-landscape/)
- [DNS Tunneling Campaigns (Unit42)](https://unit42.paloaltonetworks.com/three-dns-tunneling-campaigns/)

---

**Document Version**: 1.0
**Analysis Date**: February 2025
**Total Security Items**: 9 core vulnerabilities + comprehensive checklist
