package com.kvlogic.springsecex.repo;

import com.kvlogic.springsecex.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo  extends JpaRepository<Users,Integer> {
    Users findByUsername(String username);

}

