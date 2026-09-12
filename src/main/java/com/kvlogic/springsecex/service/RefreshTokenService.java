package com.kvlogic.springsecex.service;

import com.kvlogic.springsecex.model.RefreshToken;
import com.kvlogic.springsecex.model.Users;
import com.kvlogic.springsecex.repo.RefreshTokenRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Production Refresh Token Service
 * Implements Refresh Token Rotation (RTR) and Token Family Replay/Reuse Detection.
 *
 * If an already-used token is submitted, the server detects token theft and invalidates
 * the ENTIRE token family immediately to protect the user's account.
 */
@Service
public class RefreshTokenService {

    @Value("${jwt.refresh-token.expiration-ms:604800000}") // Default: 7 days
    private long refreshTokenExpirationMs;

    @Autowired
    private RefreshTokenRepo refreshTokenRepo;

    @Transactional
    public RefreshToken createRefreshToken(Users user) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setTokenFamily(UUID.randomUUID().toString()); // New family for fresh login
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpirationMs));
        refreshToken.setRevoked(false);
        refreshToken.setUsed(false);
        refreshToken.setCreatedAt(Instant.now());

        return refreshTokenRepo.save(refreshToken);
    }

    /**
     * Refresh Token Rotation (RTR)
     * Validates the presented token, detects reuse, marks old token as used, and returns new token.
     */
    @Transactional
    public RefreshToken rotateRefreshToken(String requestToken) {
        RefreshToken token = refreshTokenRepo.findByToken(requestToken)
                .orElseThrow(() -> new RuntimeException("Refresh token not found in system"));

        // 1. Check if token is marked as revoked
        if (token.isRevoked()) {
            refreshTokenRepo.revokeTokenFamily(token.getTokenFamily());
            throw new RuntimeException("Refresh token revoked. Session terminated.");
        }

        // 2. REUSE DETECTION: If this token was already used, a replay/theft attack is occurring!
        if (token.isUsed()) {
            // Revoke the ENTIRE family immediately
            refreshTokenRepo.revokeTokenFamily(token.getTokenFamily());
            System.err.println("🚨 SECURITY ALERT: Refresh token reuse detected for family " + token.getTokenFamily() + "! Revoking all sessions.");
            throw new RuntimeException("SECURITY ALERT: Refresh token reuse detected! All related sessions have been revoked. Please log in again.");
        }

        // 3. Expiration check
        if (token.getExpiryDate().isBefore(Instant.now())) {
            token.setRevoked(true);
            refreshTokenRepo.save(token);
            throw new RuntimeException("Refresh token has expired. Please log in again.");
        }

        // 4. Mark old token as used (cannot be used again)
        token.setUsed(true);
        refreshTokenRepo.save(token);

        // 5. Issue new child token in the SAME token family
        RefreshToken nextToken = new RefreshToken();
        nextToken.setUser(token.getUser());
        nextToken.setToken(UUID.randomUUID().toString());
        nextToken.setTokenFamily(token.getTokenFamily()); // Keep same lineage
        nextToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpirationMs));
        nextToken.setRevoked(false);
        nextToken.setUsed(false);
        nextToken.setCreatedAt(Instant.now());

        return refreshTokenRepo.save(nextToken);
    }

    @Transactional
    public void revokeToken(String tokenString) {
        Optional<RefreshToken> tokenOpt = refreshTokenRepo.findByToken(tokenString);
        if (tokenOpt.isPresent()) {
            RefreshToken token = tokenOpt.get();
            token.setRevoked(true);
            refreshTokenRepo.revokeTokenFamily(token.getTokenFamily());
        }
    }

    @Transactional
    public void revokeAllForUser(Users user) {
        refreshTokenRepo.revokeAllForUser(user);
    }

    public long getRefreshTokenExpirationSeconds() {
        return refreshTokenExpirationMs / 1000;
    }
}
