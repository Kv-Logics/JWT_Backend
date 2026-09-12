package com.kvlogic.springsecex.service;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Production Pattern: In-memory token denylist (blacklisting) via unique JWT ID (jti).
 * When an access token is revoked before its expiration (e.g., user logout), its jti
 * is stored in the denylist until its natural expiration.
 * In a multi-instance microservices architecture, this can easily be backed by Redis.
 */
@Service
public class TokenDenylistService {

    private final Map<String, Instant> denylist = new ConcurrentHashMap<>();

    public void denylistToken(String jti, Instant expiry) {
        if (jti != null && expiry != null && expiry.isAfter(Instant.now())) {
            denylist.put(jti, expiry);
        }
    }

    public boolean isDenylisted(String jti) {
        if (jti == null) {
            return false;
        }
        Instant expiry = denylist.get(jti);
        if (expiry == null) {
            return false;
        }
        if (expiry.isBefore(Instant.now())) {
            denylist.remove(jti);
            return false;
        }
        return true;
    }

    // Prune expired entries periodically to prevent memory accumulation
    public void cleanup() {
        Instant now = Instant.now();
        denylist.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
    }

    public int getDenylistedCount() {
        return denylist.size();
    }
}
