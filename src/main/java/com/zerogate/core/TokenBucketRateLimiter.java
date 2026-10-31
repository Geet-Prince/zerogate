// src/main/java/com/zerogate/core/TokenBucketRateLimiter.java
package com.zerogate.core;

import org.springframework.stereotype.Component;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TokenBucketRateLimiter {
    private static final long CAPACITY = 10;
    private static final double REFILL_TOKENS_PER_NANO = 10.0 / 60_000_000_000.0;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public static class Bucket {
        private double tokens = CAPACITY;
        private long lastRefillNano = System.nanoTime();

        public synchronized int tryConsume() {
            long now = System.nanoTime();
            double refill = (now - lastRefillNano) * REFILL_TOKENS_PER_NANO;
            if (refill > 0) {
                tokens = Math.min(CAPACITY, tokens + refill);
                lastRefillNano = now;
            }
            if (tokens >= 1.0) {
                tokens -= 1.0;
                return (int) Math.floor(tokens);
            }
            return -1;
        }
    }

    public int tryConsume(String key) {
        return buckets.computeIfAbsent(key, k -> new Bucket()).tryConsume();
    }

    public int getActiveBucketsCount() {
        return buckets.size();
    }
}
