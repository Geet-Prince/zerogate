# zerogate

A lightweight Zero-Trust API Gateway and inline security filter built with Java 17 and Spring Boot 3.3.

## Why I Built This

Most production API gateways immediately pull in Redis, distributed key-value stores, or third-party rate-limiting frameworks like Bucket4j or Resilience4j. While necessary at massive scale, pulling heavy infrastructure dependencies for intermediate gateways adds network hops, deployment friction, and maintenance overhead.

I built `zerogate` to explore how far pure Java (`java.util.concurrent` and `javax.crypto`) can take you when building core gateway primitives from first principles:
- In-memory thread-safe generic LRU cache with TTL eviction.
- Zero-allocation lazy Token Bucket rate limiting per client IP.
- Inline regex-based WAF inspection against SQLi and XSS before payload reaches handlers.
- Micro-segmentation request signing via HMAC-SHA256 to guarantee request integrity to downstream services.

No Redis. No Lombok. No external rate-limiting libraries. Just standard Spring Web and JJWT.

---

## Request Lifecycle / Architecture

Every incoming request matching `/api/**` traverses a 4-stage pipeline before touching downstream business logic:

```text
Incoming HTTP Request (/api/**)
       │
       ▼
┌────────────────────────────────────────────────────────┐
│ Stage 1: Inline WAF Inspection                         │
│ - Decode query string & inspect custom headers         │
│ - Match SQLi (?i).*(\bunion|select|drop|...|1=1).*     │
│ - Match XSS  (?i).*<script.*                           │
└────────────────────────────────────────────────────────┘
       │  Match -> 403 Forbidden
       ▼  Pass
┌────────────────────────────────────────────────────────┐
│ Stage 2: Token Bucket Rate Limiter                     │
│ - Keyed by Client IP (ConcurrentHashMap<IP, Bucket>)   │
│ - Capacity: 10 tokens, Refill: 10 tokens / 60s         │
│ - Lazy token calculation via System.nanoTime()         │
└────────────────────────────────────────────────────────┘
       │  Exceeded -> 429 Too Many Requests
       ▼  Pass (sets X-RateLimit-Remaining)
┌────────────────────────────────────────────────────────┐
│ Stage 3: Zero-Trust Auth & In-Memory LRU Cache         │
│ - Extract Bearer JWT token                             │
│ - Cache lookup (LruTtlCache<token, Claims>)            │
│   ├─ Hit: reuse cached claims                          │
│   └─ Miss: verify signature via JJWT -> write to cache │
│ - Enforce RBAC (ADMIN required for POST/DELETE)        │
└────────────────────────────────────────────────────────┘
       │  Invalid / Expired -> 401 Unauthorized
       │  Insufficient Role -> 403 Forbidden
       ▼  Pass
┌────────────────────────────────────────────────────────┐
│ Stage 4: Downstream Signing & Async Audit              │
│ - Compute HMAC-SHA256(URI + subject + timestamp)       │
│ - Stamp X-ZeroTrust-Signature header                   │
│ - Non-blocking audit log via CompletableFuture         │
└────────────────────────────────────────────────────────┘
       │
       ▼
Downstream Controller / Microservice
```

---

## Key Engineering Decisions

- **Lock Contention vs. Access Order in `LruTtlCache`**: `LinkedHashMap(..., true)` modifies entry pointers on read operations to track access order. Because reads mutate internal pointers, a standard read-lock is insufficient without risking structural race conditions. Write locks guard `get()` and `put()`, keeping the implementation strictly thread-safe without needing complex lock-free skip-lists.
- **Lazy Nano-Time Token Bucket Refill**: Avoided background timers or daemon threads ticking every second to refill buckets. Refill math is computed lazily on demand during `tryConsume()` using elapsed `System.nanoTime()`. Zero idle CPU usage when traffic is low.
- **Downstream Verification via `X-ZeroTrust-Signature`**: In a zero-trust model, perimeter auth is not enough. Downstream services must not trust headers without cryptographic proof. Stamping each routed request with an HMAC-SHA256 hash of the URI, authenticated subject, and timestamp allows downstream targets to independently verify that the request traversed this gateway and was not forged internally.

---

## Quick Start & cURL Verification

### Run Application

```bash
mvn clean package
mvn spring-boot:run
```

The gateway listens on port `8080`.

### 1. Issue JWT Token

```bash
curl -s -X POST "http://localhost:8080/auth/token?user=prince&role=ADMIN"
```

**Response:**
```json
{
  "role": "ADMIN",
  "user": "prince",
  "token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

### 2. Valid Protected Request

Save token to variable and send GET request:

```bash
TOKEN=$(curl -s -X POST "http://localhost:8080/auth/token?user=prince&role=ADMIN" | sed -E 's/.*"token":"([^"]+)".*/\1/')

curl -i -X GET "http://localhost:8080/api/v1/courses" \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**
```http
HTTP/1.1 200 OK
X-RateLimit-Remaining: 9
X-ZeroTrust-Signature: a1b2c3d4e5...
Content-Type: application/json

{
  "service": "Downstream-Course-Service",
  "zeroTrustVerified": true,
  "authenticatedUser": "prince",
  "role": "ADMIN",
  "X-ZeroTrust-Signature": "a1b2c3d4e5...",
  "courses": [
    "CS301-Computer-Networks",
    "CS302-Operating-Systems",
    "CS303-Zero-Trust-Security"
  ]
}
```

### 3. Trigger WAF SQLi Block (403)

```bash
curl -i -X GET "http://localhost:8080/api/v1/courses?query=1%20OR%201=1" \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "status": 403,
  "error": "ZeroGate WAF: Malicious SQLi/XSS payload blocked"
}
```

### 4. Telemetry and Cache Hit Stats

```bash
curl -s "http://localhost:8080/admin/telemetry"
```

**Response:**
```json
{
  "totalRequests": 12,
  "wafBlocks": 1,
  "rateLimitDrops": 0,
  "authFailures": 0,
  "activeRateLimitBuckets": 1,
  "lruCacheHits": 9,
  "lruCacheMisses": 1,
  "lruCacheHitRatio": 0.9
}
```
