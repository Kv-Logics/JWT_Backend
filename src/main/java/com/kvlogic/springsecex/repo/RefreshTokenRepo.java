package com.kvlogic.springsecex.repo;

import com.kvlogic.springsecex.model.RefreshToken;
import com.kvlogic.springsecex.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepo extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByTokenFamily(String tokenFamily);

    @Modifying
    @Query("UPDATE RefreshToken r SET r.revoked = true WHERE r.tokenFamily = :tokenFamily")
    int revokeTokenFamily(String tokenFamily);

    @Modifying
    @Query("UPDATE RefreshToken r SET r.revoked = true WHERE r.user = :user")
    int revokeAllForUser(Users user);

    void deleteByUser(Users user);

    void deleteByExpiryDateBefore(Instant now);
}
