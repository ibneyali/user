package com.orders.user.services;

/**
 * @author Ibney Ali
 */

public interface EmailService {
    void sendPasswordResetEmail(String to, String token);
}
