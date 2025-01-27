package com.orders.user.controllers;

import com.orders.user.dto.UpdatePasswordDto;
import com.orders.user.entities.User;
import com.orders.user.exception.EmailOrPasswordException;
import com.orders.user.exception.UserAlreadyExistsException;
import com.orders.user.dto.LoginUserDto;
import com.orders.user.dto.RegisterUserDto;
import com.orders.user.responses.LoginResponse;
import com.orders.user.responses.RegistrationResponse;
import com.orders.user.services.AdminService;
import com.orders.user.services.impl.JwtServiceImpl;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;
import java.util.logging.Logger;

/**
 * @author Ibney Ali
 */

@Slf4j
@RequestMapping("/api/admin")
@RestController
public class AdminController {

	Logger logger = Logger.getLogger(AdminController.class.getName());

	@Autowired
	JwtServiceImpl jwtService;

	@Autowired
	AdminService adminService;

	@PostMapping("/registration")
	public ResponseEntity<RegistrationResponse> register(@RequestBody RegisterUserDto registerUserDto) {
		logger.info("Registering user: " + registerUserDto);
		RegistrationResponse registeredUser = adminService.signup(registerUserDto);
		logger.info("Registering success: " + registeredUser);
		return ResponseEntity.ok(registeredUser);
	}

	@GetMapping("/verify")
    public ResponseEntity<String> verifyEmail(@RequestParam("token") String token) {
        boolean isVerified = adminService.verifyEmail(token);
        if (isVerified) {
            return ResponseEntity.ok("Email verified successfully.");
        } else {
            return ResponseEntity.badRequest().body("Invalid or expired token.");
        }
    }

	@PostMapping("/login")
	public ResponseEntity<LoginResponse> loginWithCred(@RequestBody LoginUserDto loginUserDto) {
		logger.info("Logging in user: " + loginUserDto);
		try {
			User authenticatedUser = adminService.authenticate(loginUserDto);
			logger.info("User authenticated: " + authenticatedUser);
			String jwtToken = jwtService.generateToken(authenticatedUser);
			LoginResponse loginResponse = new LoginResponse();
			loginResponse.setExpiresIn(jwtService.getExpirationTime());
			loginResponse.setSuccessMessage("Login successful.");
			loginResponse.setToken(jwtToken);
			logger.info("Login success: " + loginResponse);
			return ResponseEntity.ok(loginResponse);
		} catch (UserAlreadyExistsException e) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body(null);
		}
	}

	@PostMapping("/forgot-password")
	public ResponseEntity<Map<String, String>> forgotPassword(@RequestParam String email, HttpServletRequest request) {
		logger.info("Forgot password for email: " + email);
		Map<String, String> response = adminService.forgotPassword(email, request);
		logger.info("Forgot password response: " + response);
		return ResponseEntity.ok(response);
	}

	@GetMapping("/reset-password")
	public ResponseEntity<String> resetPassword(@RequestParam("token") String token, HttpServletResponse response) {
		logger.info("Reset password token: " + token);
		adminService.validatePasswordResetToken(token);
		try {
			response.sendRedirect("http://localhost:3000/update-password?token=" + token);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return ResponseEntity.ok("Redirecting to update password page.");
	}

	@PutMapping("/update-password")
	public ResponseEntity<String> updatePassword(@RequestBody UpdatePasswordDto updatePasswordDto) {
		logger.info("Updating password for token: " + updatePasswordDto.getToken());
		try {
			adminService.updatePassword(updatePasswordDto.getToken(), updatePasswordDto.getPassword(), updatePasswordDto.getConfirmPassword());
			logger.info("Password updated successfully.");
			return ResponseEntity.ok("Password updated successfully.");
		} catch (EmailOrPasswordException e) {
			return ResponseEntity.badRequest().body("Invalid token or password.");
		}
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout() {
		adminService.logout();
		return ResponseEntity.ok().build();
	}

}