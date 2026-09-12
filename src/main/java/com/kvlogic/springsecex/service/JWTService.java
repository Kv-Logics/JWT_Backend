package com.kvlogic.springsecex.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.io.Decoders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * Advanced Production JWT Service
 * Implements standard production claims: iss, sub, aud, exp, iat, nbf, jti, typ, roles, scopes.
 * Includes clock-skew leeway (60s), audience & issuer validation, and denylist (jti) checks.
 */
@Service
public class JWTService {

    @Value("${jwt.secret:TmV3U2VjcmV0S2V5Rm9ySldTU2lnbmluZ1B1cnBvc2VzSW5MYXllcmVkQXJjaGl0ZWN0dXJl}")
    private String secretKey;

    @Value("${jwt.issuer:https://auth.kvlogics.com}")
    private String issuer;

    @Value("${jwt.audience:https://api.kvlogics.com}")
    private String audience;

    @Value("${jwt.access-token.expiration-ms:900000}") // Default: 15 minutes
    private long accessTokenExpirationMs;

    @Autowired
    private TokenDenylistService denylistService;

    public String generateAccessToken(String username, String role, String scope) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date expiryDate = new Date(nowMillis + accessTokenExpirationMs);
        String jti = UUID.randomUUID().toString();

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("role", role);
        customClaims.put("scope", scope != null ? scope : (role.equals("ADMIN") ? "students:read students:write students:delete" : "students:read"));
        customClaims.put("typ", "ACCESS");

        return Jwts.builder()
                .issuer(issuer)
                .audience().add(audience).and()
                .subject(username)
                .id(jti)
                .issuedAt(now)
                .notBefore(now)
                .expiration(expiryDate)
                .claims(customClaims)
                .signWith(getKey())
                .compact();
    }

    // Backward-compatible overload
    public String generateToken(String username, String role) {
        return generateAccessToken(username, role, null);
    }

    private SecretKey getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    public String extractScope(String token) {
        return extractClaim(token, claims -> claims.get("scope", String.class));
    }

    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .requireIssuer(issuer)
                .requireAudience(audience)
                .clockSkewSeconds(60) // Leeway for distributed clocks
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            final Claims claims = extractAllClaims(token);
            final String username = claims.getSubject();
            final String jti = claims.getId();

            // 1. Check if username matches
            if (!username.equals(userDetails.getUsername())) {
                return false;
            }

            // 2. Check if token is expired
            if (claims.getExpiration().before(new Date())) {
                return false;
            }

            // 3. Check if token's jti is in the revocation denylist
            if (denylistService.isDenylisted(jti)) {
                return false;
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public long getAccessTokenExpirationSeconds() {
        return accessTokenExpirationMs / 1000;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getAudience() {
        return audience;
    }
}