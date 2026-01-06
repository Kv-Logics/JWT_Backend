package com.kvlogic.springsecex.service;

import com.kvlogic.springsecex.model.Users;
import com.kvlogic.springsecex.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserRepo repo;
    @Autowired
    private JWTService jwtService;
    @Autowired
    AuthenticationManager authManager;

    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public Users register(Users user) {
        user.setPassword(encoder.encode(user.getPassword()));
        // Set default role if not provided
        if(user.getRole() == null) {
            user.setRole("USER");
        }
        return repo.save(user);
    }

    public String verify(Users user) {
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
        );

        if (authentication.isAuthenticated()) {
            // Fetch user to get their role
            Users dbUser = repo.findByUsername(user.getUsername());
            String role = dbUser.getRole() == null ? "USER" : dbUser.getRole();

            return jwtService.generateToken(user.getUsername(), role);
        }
        return "fail";
    }
}