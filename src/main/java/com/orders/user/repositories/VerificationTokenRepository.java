package com.orders.user.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.orders.user.entities.VerificationToken;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
    VerificationToken findByToken(String token);
}
