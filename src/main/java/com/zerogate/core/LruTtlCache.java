// src/main/java/com/zerogate/core/LruTtlCache.java
package com.zerogate.core;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class LruTtlCache<K, V> {
    private static class CacheEntry<V> {
        final V value;
        final long expiryNano;
        CacheEntry(V value, long ttlMillis) {
            this.value = value;
            this.expiryNano = System.nanoTime() + (ttlMillis * 1_000_000L);
        }
        boolean isExpired() {
            return System.nanoTime() > expiryNano;
        }
    }

    private final int capacity;
    private final long ttlMillis;
    private final Map<K, CacheEntry<V>> map;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final AtomicLong hits = new AtomicLong(0);
    private final AtomicLong misses = new AtomicLong(0);

    public LruTtlCache(int capacity, long ttlMillis) {
        this.capacity = capacity;
        this.ttlMillis = ttlMillis;
        this.map = new LinkedHashMap<>(capacity, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, CacheEntry<V>> eldest) {
                return size() > LruTtlCache.this.capacity;
            }
        };
    }

    public V get(K key) {
        lock.writeLock().lock();
        try {
            CacheEntry<V> entry = map.get(key);
            if (entry == null) {
                misses.incrementAndGet();
                return null;
            }
            if (entry.isExpired()) {
                map.remove(key);
                misses.incrementAndGet();
                return null;
            }
            hits.incrementAndGet();
            return entry.value;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void put(K key, V value) {
        lock.writeLock().lock();
        try {
            map.put(key, new CacheEntry<>(value, ttlMillis));
        } finally {
            lock.writeLock().unlock();
        }
    }

    public long getHits() { return hits.get(); }
    public long getMisses() { return misses.get(); }
    public double getHitRatio() {
        long h = hits.get();
        long total = h + misses.get();
        return total == 0 ? 0.0 : (double) h / total;
    }
}
