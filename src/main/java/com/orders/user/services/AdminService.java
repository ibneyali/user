package com.orders.user.services;

import com.orders.user.dto.LoginUserDto;
import com.orders.user.dto.RegisterUserDto;
import com.orders.user.entities.User;
import com.orders.user.responses.RegistrationResponse;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;

/**
 * @author Ibney Ali
 */

public interface AdminService {

    RegistrationResponse signup(RegisterUserDto input);
    User authenticate(LoginUserDto input);
    Map<String, String> forgotPassword(String email, HttpServletRequest request);
    User validatePasswordResetToken(String token);
    void updatePassword(String token, String password, String confirmPassword);
    void logout();
    boolean verifyEmail(String token);
}
