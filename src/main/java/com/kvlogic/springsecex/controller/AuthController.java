package com.kvlogic.springsecex.controller;

import com.kvlogic.springsecex.dto.ApiResponse;
import com.kvlogic.springsecex.dto.AuthRequest;
import com.kvlogic.springsecex.dto.AuthResponse;
import com.kvlogic.springsecex.dto.RefreshTokenRequest;
import com.kvlogic.springsecex.model.Users;
import com.kvlogic.springsecex.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AuthController {

    @Autowired
    private UserService userService;

    @PostMapping({"/api/auth/register", "/register"})
    public ResponseEntity<ApiResponse<?>> register(@RequestBody Users user) {
        try {
            Users registered = userService.register(user);
            registered.setPassword(null); // Never return password in response
            return ResponseEntity.ok(ApiResponse.ok("User registered successfully", registered));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(e.getMessage()));
        }
    }

    @PostMapping({"/api/auth/login", "/login"})
    public ResponseEntity<ApiResponse<?>> login(@RequestBody AuthRequest request) {
        try {
            AuthResponse response = userService.authenticate(request);
            return ResponseEntity.ok(ApiResponse.ok("Login successful", response));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Invalid username or password"));
        }
    }

    @PostMapping({"/api/auth/refresh", "/refresh"})
    public ResponseEntity<ApiResponse<?>> refresh(@RequestBody RefreshTokenRequest request) {
        try {
            if (request.getRefreshToken() == null || request.getRefreshToken().isBlank()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ApiResponse.error("Refresh token is required"));
            }
            AuthResponse response = userService.refreshToken(request.getRefreshToken());
            return ResponseEntity.ok(ApiResponse.ok("Token refreshed successfully", response));
        } catch (Exception e) {
            // Can be token expired, or reuse detected
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(e.getMessage()));
        }
    }

    @PostMapping({"/api/auth/logout", "/logout"})
    public ResponseEntity<ApiResponse<String>> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody(required = false) RefreshTokenRequest request) {
        try {
            String refreshToken = (request != null) ? request.getRefreshToken() : null;
            userService.logout(authHeader, refreshToken);
            return ResponseEntity.ok(ApiResponse.ok("Logged out successfully. Tokens revoked.", null));
        } catch (Exception e) {
            return ResponseEntity.ok(ApiResponse.ok("Logged out.", null));
        }
    }

    @GetMapping({"/api/auth/me", "/me"})
    public ResponseEntity<ApiResponse<?>> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Not authenticated"));
        }

        Map<String, Object> profile = new HashMap<>();
        profile.put("username", authentication.getName());
        profile.put("authorities", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        Users user = userService.getUserByUsername(authentication.getName());
        if (user != null) {
            profile.put("id", user.getId());
            profile.put("role", user.getRole());
        }

        return ResponseEntity.ok(ApiResponse.ok("User profile retrieved", profile));
    }
}
