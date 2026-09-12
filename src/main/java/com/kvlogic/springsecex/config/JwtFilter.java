package com.kvlogic.springsecex.config;

import com.kvlogic.springsecex.service.JWTService;
import com.kvlogic.springsecex.service.MyUserDetailsService;
import com.kvlogic.springsecex.service.TokenDenylistService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Production JWT Filter
 * Extracts Bearer token, validates against clock skew, issuer, audience, and denylist (jti),
 * maps both Roles and Scopes into GrantedAuthorities, and tags JWT error codes for client interceptors.
 */
@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;

    @Autowired
    private TokenDenylistService denylistService;

    @Autowired
    private ApplicationContext context;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/api/auth/") || 
               path.equals("/login") || 
               path.equals("/register") || 
               path.equals("/refresh") || 
               path.equals("/logout") || 
               path.equals("/error");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7).trim();
            try {
                // Check denylist before proceeding
                String jti = jwtService.extractJti(token);
                if (jti != null && denylistService.isDenylisted(jti)) {
                    request.setAttribute("jwt_error_code", "TOKEN_REVOKED");
                    request.setAttribute("jwt_error_message", "Token has been revoked. Please re-authenticate.");
                } else {
                    username = jwtService.extractUserName(token);
                }
            } catch (ExpiredJwtException e) {
                request.setAttribute("jwt_error_code", "TOKEN_EXPIRED");
                request.setAttribute("jwt_error_message", "Access token has expired. Use refresh token to renew.");
            } catch (SignatureException e) {
                request.setAttribute("jwt_error_code", "INVALID_SIGNATURE");
                request.setAttribute("jwt_error_message", "JWT signature verification failed.");
            } catch (MalformedJwtException e) {
                request.setAttribute("jwt_error_code", "MALFORMED_TOKEN");
                request.setAttribute("jwt_error_message", "Malformed or unparseable JWT.");
            } catch (Exception e) {
                request.setAttribute("jwt_error_code", "INVALID_TOKEN");
                request.setAttribute("jwt_error_message", e.getMessage());
            }
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(username);

            if (jwtService.validateToken(token, userDetails)) {
                List<GrantedAuthority> authorities = new ArrayList<>(userDetails.getAuthorities());

                // Extract Scopes if present and attach as SCOPE_<name> authorities
                try {
                    String scopeClaim = jwtService.extractScope(token);
                    if (scopeClaim != null && !scopeClaim.isBlank()) {
                        for (String scope : scopeClaim.split("\\s+")) {
                            authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
                        }
                    }
                } catch (Exception ignored) {
                }

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
