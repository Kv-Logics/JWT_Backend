package com.kvlogic.springsecex.config;

import com.kvlogic.springsecex.model.Users;
import com.kvlogic.springsecex.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class AdminSeeder implements CommandLineRunner {

    @Autowired
    private UserRepo userRepo; // Fixed: Changed from UserRepository to UserRepo

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // 1. Check if the fixed admin already exists using 'username'
        String adminUsername = "admin";

        if (userRepo.findByUsername(adminUsername) == null) {
            // 2. If not, create it immediately
            Users admin = new Users(); // Fixed: Changed from User to Users

            admin.setUsername(adminUsername); // Fixed: Used setUsername instead of setEmail
            admin.setRole("ADMIN"); // Matches the "hasRole('ADMIN')" check in SecurityConfig

            // 3. Hardcode the password here (Encoded)
            admin.setPassword(passwordEncoder.encode("admin123"));


            userRepo.save(admin);
            System.out.println("🚀 SHOWCASE MODE: Admin created (username: 'admin' / password: 'admin123')");
        }
    }
}