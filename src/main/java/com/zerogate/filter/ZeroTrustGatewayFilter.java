// src/main/java/com/zerogate/filter/ZeroTrustGatewayFilter.java
package com.zerogate.filter;

import com.zerogate.core.LruTtlCache;
import com.zerogate.core.TokenBucketRateLimiter;
import com.zerogate.security.CryptoAndJwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

@Component
public class ZeroTrustGatewayFilter extends OncePerRequestFilter {
    private static final Pattern SQLI_PATTERN = Pattern.compile("(?i).*(\\b(union|select|insert|drop|delete|update)\\b|--|;|\\bOR\\b\\s+1=1).*");
    private static final Pattern XSS_PATTERN = Pattern.compile("(?i).*<script.*");

    private final TokenBucketRateLimiter rateLimiter;
    private final CryptoAndJwtUtil cryptoUtil;
    private final LruTtlCache<String, Claims> tokenCache = new LruTtlCache<>(256, 300_000);

    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong wafBlocks = new AtomicLong(0);
    private final AtomicLong rateLimitDrops = new AtomicLong(0);
    private final AtomicLong authFailures = new AtomicLong(0);

    public ZeroTrustGatewayFilter(TokenBucketRateLimiter rateLimiter, CryptoAndJwtUtil cryptoUtil) {
        this.rateLimiter = rateLimiter;
        this.cryptoUtil = cryptoUtil;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        totalRequests.incrementAndGet();
        String clientIp = req.getRemoteAddr();

        // Stage 1: Inline WAF Inspection (Query String & Headers)
        if (isMaliciousPayload(req)) {
            wafBlocks.incrementAndGet();
            logAsync("WAF_BLOCK", clientIp, req.getRequestURI());
            sendJsonError(res, 403, "ZeroGate WAF: Malicious SQLi/XSS payload blocked");
            return;
        }

        // Stage 2: Token Bucket Rate Limiting
        int remaining = rateLimiter.tryConsume(clientIp);
        if (remaining < 0) {
            rateLimitDrops.incrementAndGet();
            res.setHeader("X-RateLimit-Remaining", "0");
            logAsync("RATE_LIMIT_DROP", clientIp, req.getRequestURI());
            sendJsonError(res, 429, "ZeroGate Rate Limiter: Quota exceeded (Max 10 req/min)");
            return;
        }
        res.setHeader("X-RateLimit-Remaining", String.valueOf(remaining));

        // Stage 3: Zero-Trust Auth, LRU Cache Lookup & RBAC Enforcement
        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            authFailures.incrementAndGet();
            sendJsonError(res, 401, "ZeroGate Auth: Missing Bearer JWT token");
            return;
        }

        String token = authHeader.substring(7);
        Claims claims = tokenCache.get(token);
        if (claims == null) {
            try {
                claims = cryptoUtil.validateToken(token);
                tokenCache.put(token, claims);
            } catch (Exception e) {
                authFailures.incrementAndGet();
                sendJsonError(res, 401, "ZeroGate Auth: Invalid or expired JWT token");
                return;
            }
        }

        String role = claims.get("role", String.class);
        String method = req.getMethod();
        if (("POST".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method)) && !"ADMIN".equalsIgnoreCase(role)) {
            authFailures.incrementAndGet();
            sendJsonError(res, 403, "ZeroGate RBAC: ADMIN privilege required for state-mutating operations");
            return;
        }

        // Stage 4: Downstream Micro-Segmentation Signing & Async Audit
        long ts = System.currentTimeMillis();
        String signature = cryptoUtil.computeHmacSha256(req.getRequestURI() + "|" + claims.getSubject() + "|" + ts);
        req.setAttribute("X-ZeroTrust-Signature", signature);
        req.setAttribute("X-Authenticated-User", claims.getSubject());
        req.setAttribute("X-Authenticated-Role", role);
        res.setHeader("X-ZeroTrust-Signature", signature);

        logAsync("ALLOW", claims.getSubject(), req.getRequestURI());
        chain.doFilter(req, res);
    }

    private boolean isMaliciousPayload(HttpServletRequest req) {
        String rawQuery = req.getQueryString();
        if (rawQuery != null) {
            String decoded = URLDecoder.decode(rawQuery, StandardCharsets.UTF_8);
            if (SQLI_PATTERN.matcher(decoded).matches() || XSS_PATTERN.matcher(decoded).matches()) {
                return true;
            }
        }
        for (String headerName : Collections.list(req.getHeaderNames())) {
            if ("Authorization".equalsIgnoreCase(headerName)) continue;
            String val = req.getHeader(headerName);
            if (val != null && (SQLI_PATTERN.matcher(val).matches() || XSS_PATTERN.matcher(val).matches())) {
                return true;
            }
        }
        return false;
    }

    private void logAsync(String event, String actor, String uri) {
        CompletableFuture.runAsync(() ->
            System.out.printf("[ZeroGate-Audit] event=%s actor=%s uri=%s ts=%d%n", event, actor, uri, System.currentTimeMillis())
        );
    }

    private void sendJsonError(HttpServletResponse res, int status, String msg) throws IOException {
        res.setStatus(status);
        res.setContentType("application/json");
        res.getWriter().write(String.format("{\"status\":%d,\"error\":\"%s\"}", status, msg));
    }

    public Map<String, Object> getTelemetry() {
        return Map.of(
            "totalRequests", totalRequests.get(),
            "wafBlocks", wafBlocks.get(),
            "rateLimitDrops", rateLimitDrops.get(),
            "authFailures", authFailures.get(),
            "activeRateLimitBuckets", rateLimiter.getActiveBucketsCount(),
            "lruCacheHits", tokenCache.getHits(),
            "lruCacheMisses", tokenCache.getMisses(),
            "lruCacheHitRatio", tokenCache.getHitRatio()
        );
    }
}
