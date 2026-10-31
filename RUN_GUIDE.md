# ZeroGate — Step-by-Step Run & Test Guide

This guide walks you through building, starting, and verifying all security layers in **zerogate**.

---

## Prerequisites

- **Java**: JDK 17 or higher (`java -version`)
- **Maven**: 3.8+ (`mvn -version`)
- **cURL**: Installed on macOS/Linux/WSL by default

---

## 1. Build & Start the Server

From the project root directory:

```bash
# 1. Clean and package the application
mvn clean package

# 2. Run with Maven
mvn spring-boot:run
```

*(Alternatively, run the compiled JAR directly)*:
```bash
java -jar target/zerogate-1.0.0.jar
```

The gateway starts on **`http://localhost:8080`**. Keep this terminal window open.

---

## 2. Verify Initial Health

Open a new terminal tab and check the gateway telemetry:

```bash
curl -s http://localhost:8080/admin/telemetry
```

Or open directly in your browser:
👉 **[http://localhost:8080/admin/telemetry](http://localhost:8080/admin/telemetry)**

**Initial Output:**
```json
{
  "totalRequests": 0,
  "wafBlocks": 0,
  "rateLimitDrops": 0,
  "authFailures": 0,
  "activeRateLimitBuckets": 0,
  "lruCacheHits": 0,
  "lruCacheMisses": 0,
  "lruCacheHitRatio": 0.0
}
```

---

## 3. Complete Step-by-Step Test Scenarios

### Step A: Issue JWT Tokens

ZeroGate issues signed JWTs with assigned roles:

```bash
# Generate an ADMIN token
ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8080/auth/token?user=prince&role=ADMIN" | sed -E 's/.*"token":"([^"]+)".*/\1/')
echo "ADMIN_TOKEN: $ADMIN_TOKEN"

# Generate a STUDENT token
STUDENT_TOKEN=$(curl -s -X POST "http://localhost:8080/auth/token?user=alex&role=STUDENT" | sed -E 's/.*"token":"([^"]+)".*/\1/')
echo "STUDENT_TOKEN: $STUDENT_TOKEN"
```

---

### Step B: Test Authenticated Read (`GET`)

Pass the Bearer token in the `Authorization` header:

```bash
curl -i -X GET "http://localhost:8080/api/v1/courses" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Expected Response (`200 OK`):**
```http
HTTP/1.1 200 OK
X-RateLimit-Remaining: 9
X-ZeroTrust-Signature: d3a4c5e6...
Content-Type: application/json

{
  "service": "Downstream-Course-Service",
  "zeroTrustVerified": true,
  "authenticatedUser": "prince",
  "role": "ADMIN",
  "X-ZeroTrust-Signature": "d3a4c5e6...",
  "courses": [
    "CS301-Computer-Networks",
    "CS302-Operating-Systems",
    "CS303-Zero-Trust-Security"
  ]
}
```

---

### Step C: Test LRU Cache Acceleration

Run the same request a second time:

```bash
curl -s -X GET "http://localhost:8080/api/v1/courses" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

- **Request 1**: Decodes token, validates cryptographic signature, saves to cache (Miss: 1, Hit: 0).
- **Request 2**: Fetches claims directly from in-memory cache without repeating signature parsing (Miss: 1, Hit: 1).

---

### Step D: Test Role-Based Access Control (RBAC)

Mutating endpoints (`POST` / `DELETE`) require `ADMIN` privilege:

#### 1. Forbidden Mutation (as `STUDENT`):
```bash
curl -i -X POST "http://localhost:8080/api/v1/grades" \
  -H "Authorization: Bearer $STUDENT_TOKEN"
```
**Response (`403 Forbidden`):**
```json
{
  "status": 403,
  "error": "ZeroGate RBAC: ADMIN privilege required for state-mutating operations"
}
```

#### 2. Allowed Mutation (as `ADMIN`):
```bash
curl -i -X POST "http://localhost:8080/api/v1/grades" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
**Response (`200 OK`):**
```json
{
  "service": "Downstream-Grade-Mutation-Service",
  "status": "GRADE_COMMITTED",
  "authorizedBy": "prince",
  "X-ZeroTrust-Signature": "..."
}
```

---

### Step E: Test Inline WAF (SQL Injection & XSS)

The gateway blocks malicious patterns in query parameters and headers:

#### 1. SQL Injection attempt (`OR 1=1`):
```bash
curl -i -X GET "http://localhost:8080/api/v1/courses?query=1%20OR%201=1" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

#### 2. XSS attempt (`<script>` tag):
```bash
curl -i -X GET "http://localhost:8080/api/v1/courses?name=<script>alert(1)</script>" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Response (`403 Forbidden` for both):**
```json
{
  "status": 403,
  "error": "ZeroGate WAF: Malicious SQLi/XSS payload blocked"
}
```

---

### Step F: Test Rate Limiting (Token Bucket)

ZeroGate enforces a maximum of 10 requests per minute per IP address. Send 12 rapid requests:

```bash
for i in {1..12}; do
  echo -n "Request #$i: "
  curl -s -o /dev/null -w "%{http_code}\n" -X GET "http://localhost:8080/api/v1/courses" \
    -H "Authorization: Bearer $ADMIN_TOKEN"
done
```

**Output:**
```text
Request #1: 200
Request #2: 200
...
Request #10: 200
Request #11: 429
Request #12: 429
```
*Requests 11 and 12 are dropped with `429 Too Many Requests` and header `X-RateLimit-Remaining: 0`.*

---

### Step G: Inspect Updated Telemetry

Check the telemetry stats to see all counters updated:

```bash
curl -s http://localhost:8080/admin/telemetry
```

**Sample Output:**
```json
{
  "totalRequests": 18,
  "wafBlocks": 2,
  "rateLimitDrops": 2,
  "authFailures": 1,
  "activeRateLimitBuckets": 1,
  "lruCacheHits": 11,
  "lruCacheMisses": 1,
  "lruCacheHitRatio": 0.916
}
```

---

## 4. Testing with Postman or Bruno

1. **Get Token**: `POST http://localhost:8080/auth/token?user=prince&role=ADMIN`
   - Copy the `token` string from the JSON response.
2. **Set Auth**: In your request to `http://localhost:8080/api/v1/courses`, open the **Authorization** tab:
   - Type: **Bearer Token**
   - Token: `<paste your token>`
3. **Send Request**: Verify status `200 OK` and check the response headers for `X-ZeroTrust-Signature` and `X-RateLimit-Remaining`.

---

## 5. Troubleshooting

- **`404 Whitelabel Error Page` on `http://localhost:8080/`**:
  - The root path (`/`) is unmapped. Open `http://localhost:8080/admin/telemetry` or call `/api/v1/courses` with a Bearer token.
- **Port 8080 already in use**:
  - Identify and terminate the existing process:
    ```bash
    lsof -ti :8080 | xargs kill -9
    ```
- **`401 Unauthorized: Missing Bearer JWT token`**:
  - Ensure the header name is `Authorization` and format is `Bearer <token>` (with a space after `Bearer`).
