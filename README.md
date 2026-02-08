# Meta Logic

**Spec-based security analysis repository for AI agent knowledge augmentation and security learning**

This project extracts meta-level security structures and vulnerability patterns by directly analyzing web standards (RFC, W3C, WHATWG), framework source code, and language standard libraries.

## Structure

```
meta-logic/
├── web-spec-analysis/          # Web standard spec security analysis
│   ├── cookie/                 # HTTP Cookies (RFC 6265)
│   ├── cors/                   # Cross-Origin Resource Sharing
│   ├── csp/                    # Content Security Policy
│   ├── dns/                    # DNS Protocol Security
│   ├── http/                   # HTTP Protocol
│   ├── json/                   # JSON Format Security
│   ├── jwt/                    # JSON Web Tokens (RFC 7519)
│   ├── oauth/                  # OAuth 2.0
│   ├── saml/                   # SAML
│   ├── tls/                    # Transport Layer Security
│   ├── url/                    # URL Parsing & Security
│   ├── webauthn/               # Web Authentication
│   ├── websocket/              # WebSocket Protocol
│   └── yaml/                   # YAML Format Security
│
├── framework-analysis/         # Framework security structure analysis
│   ├── django/                 # Django (Python)
│   ├── flask/                  # Flask (Python)
│   ├── node.js/                # Node.js Runtime
│   ├── ruby-on-rails/          # Ruby on Rails
│   └── spring/                 # Spring Framework (Java)
│
└── language-analysis/          # Language standard library security analysis
    ├── aspnet/                 # ASP.NET
    ├── html/                   # HTML Security
    ├── java/                   # Java Language & Libraries
    ├── javascript/             # JavaScript Language
    ├── php/                    # PHP Language
    └── python/                 # Python Language
```

## Use Cases

- **AI Agent Knowledge Augmentation**: Direct injection into MCP servers, RAG systems, and agent contexts
- **Security Learning**: Systematic learning through spec text → attack vectors → defense mapping
- **Vulnerability Research**: Understanding design-level security implications and architecture pattern-vulnerability relationships
- **Security Code Review**: Framework and language-specific security patterns for code auditing
- **Penetration Testing**: Protocol and implementation-level attack surface analysis

## Methodology

Each analysis follows a structured approach:

1. **Spec/Source Extraction**: Direct reading of RFC documents, W3C specs, WHATWG standards, and official source code
2. **Security Research Integration**: Latest CVEs, academic papers, BlackHat/DEF CON presentations, and security blogs
3. **Attack Vector Mapping**: Linking spec requirements (MUST/MUST NOT/SHOULD) to real-world attack patterns
4. **Defense Pattern Generation**: Creating actionable mitigation strategies based on spec compliance

## Created With

This repository was created using **Claude Code** by directly fetching and analyzing spec documents, source code, and latest security research.

## License

This is a knowledge repository for educational and research purposes.
