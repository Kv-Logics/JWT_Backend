package com.kvlogic.springsecex.service;

import com.kvlogic.springsecex.dto.AuthRequest;
import com.kvlogic.springsecex.dto.AuthResponse;
import com.kvlogic.springsecex.model.RefreshToken;
import com.kvlogic.springsecex.model.Users;
import com.kvlogic.springsecex.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class UserService {

    @Autowired
    private UserRepo repo;

    @Autowired
    private JWTService jwtService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private TokenDenylistService denylistService;

    @Autowired
    private AuthenticationManager authManager;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public Users register(Users user) {
        if (user == null || user.getUsername() == null || user.getUsername().trim().isEmpty()) {
            throw new RuntimeException("Username is required");
        }
        if (user.getPassword() == null || user.getPassword().trim().isEmpty()) {
            throw new RuntimeException("Password is required");
        }
        String cleanUsername = user.getUsername().trim();
        if (repo.existsByUsername(cleanUsername)) {
            throw new RuntimeException("Username '" + cleanUsername + "' is already taken. Please choose a different username.");
        }
        user.setUsername(cleanUsername);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setId(null); // Ensure null so Hibernate generates the ID via sequence
        if (user.getRole() == null || user.getRole().trim().isEmpty()) {
            user.setRole("USER");
        } else {
            user.setRole(user.getRole().toUpperCase().trim());
        }
        return repo.save(user);
    }

    public AuthResponse authenticate(AuthRequest request) {
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        if (authentication.isAuthenticated()) {
            Users dbUser = repo.findFirstByUsername(request.getUsername());
            String role = (dbUser.getRole() == null || dbUser.getRole().isEmpty()) ? "USER" : dbUser.getRole();
            String scope = "ADMIN".equalsIgnoreCase(role)
                    ? "students:read students:write students:delete"
                    : "students:read";

            String accessToken = jwtService.generateAccessToken(dbUser.getUsername(), role, scope);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(dbUser);

            return new AuthResponse(
                    accessToken,
                    refreshToken.getToken(),
                    jwtService.getAccessTokenExpirationSeconds(),
                    refreshToken.getTokenFamily(),
                    dbUser.getUsername(),
                    role,
                    scope
            );
        }
        throw new RuntimeException("Invalid credentials");
    }

    // Backward-compatible verify for legacy callers
    public String verify(Users user) {
        AuthResponse response = authenticate(new AuthRequest(user.getUsername(), user.getPassword()));
        return response.getAccessToken();
    }

    public AuthResponse refreshToken(String requestRefreshToken) {
        // Rotate token (RTR) and detect reuse attacks
        RefreshToken rotatedToken = refreshTokenService.rotateRefreshToken(requestRefreshToken);
        Users user = rotatedToken.getUser();
        String role = (user.getRole() == null) ? "USER" : user.getRole();
        String scope = "ADMIN".equalsIgnoreCase(role)
                ? "students:read students:write students:delete"
                : "students:read";

        String newAccessToken = jwtService.generateAccessToken(user.getUsername(), role, scope);

        return new AuthResponse(
                newAccessToken,
                rotatedToken.getToken(),
                jwtService.getAccessTokenExpirationSeconds(),
                rotatedToken.getTokenFamily(),
                user.getUsername(),
                role,
                scope
        );
    }

    public void logout(String accessToken, String refreshToken) {
        // 1. Revoke refresh token & family
        if (refreshToken != null && !refreshToken.isBlank()) {
            refreshTokenService.revokeToken(refreshToken);
        }

        // 2. Denylist the access token's jti so it cannot be reused before expiry
        if (accessToken != null && accessToken.startsWith("Bearer ")) {
            accessToken = accessToken.substring(7).trim();
        }
        if (accessToken != null && !accessToken.isBlank()) {
            try {
                String jti = jwtService.extractJti(accessToken);
                Date exp = jwtService.extractExpiration(accessToken);
                if (jti != null && exp != null) {
                    denylistService.denylistToken(jti, exp.toInstant());
                }
            } catch (Exception ignored) {
            }
        }
    }

    public Users getUserByUsername(String username) {
        return repo.findFirstByUsername(username);
    }
}