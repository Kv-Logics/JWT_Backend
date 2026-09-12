package com.kvlogic.springsecex.repo;

import com.kvlogic.springsecex.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepo extends JpaRepository<Users, Integer> {

    Users findFirstByUsername(String username);

    boolean existsByUsername(String username);

    List<Users> findAllByUsername(String username);

    // Keep for backward-compatibility
    default Users findByUsername(String username) {
        return findFirstByUsername(username);
    }
}
