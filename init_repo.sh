#!/usr/bin/env bash
set -e

REMOTE_URL="https://github.com/Geet-Prince/zerogate.git"

# Initialize git if not already initialized
if [ ! -d ".git" ]; then
  git init -b main
else
  git checkout -B main
fi

# 1. Project scaffold and configuration
git add pom.xml .gitignore
git commit -m "chore: init spring boot 3.3 maven config"

# 2. In-memory LRU Cache with TTL
git add src/main/java/com/zerogate/core/LruTtlCache.java
git commit -m "feat(cache): add thread-safe generic LRU cache with nanoTime TTL"

# 3. Token Bucket Rate Limiter
git add src/main/java/com/zerogate/core/TokenBucketRateLimiter.java
git commit -m "feat(ratelimit): implement lazy token bucket per client IP"

# 4. Crypto and JWT utilities
git add src/main/java/com/zerogate/security/CryptoAndJwtUtil.java
git commit -m "feat(security): add JWT validation and HMAC-SHA256 downstream signer"

# 5. Core Gateway filter
git add src/main/java/com/zerogate/filter/ZeroTrustGatewayFilter.java
git commit -m "feat(waf): wire inline security filter chain and async audit logging"

# 6. Spring Boot Application and mock endpoints
git add src/main/java/com/zerogate/ZerogateApplication.java
git commit -m "feat(api): expose auth, telemetry, and mock downstream endpoints"

# 7. Documentation
git add README.md
git commit -m "docs: add architecture notes and curl benchmarks"

# Configure remote and push
git remote remove origin 2>/dev/null || true
git remote add origin "$REMOTE_URL"

echo "Repository initialized with incremental commits."
echo "Pushing to $REMOTE_URL..."
git push -u origin main
