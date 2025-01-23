package com.orders.user.services.impl;

import com.orders.user.config.CustomEmailPasswordAuthenticationToken;
import com.orders.user.dto.LoginUserDto;
import com.orders.user.dto.RegisterUserDto;
import com.orders.user.entities.AuditLog;
import com.orders.user.entities.PasswordResetToken;
import com.orders.user.entities.Role;
import com.orders.user.entities.User;
import com.orders.user.enums.RoleName;
import com.orders.user.exception.*;
import com.orders.user.repositories.AuditLogRepository;
import com.orders.user.repositories.PasswordResetTokenRepository;
import com.orders.user.repositories.RoleRepository;
import com.orders.user.repositories.UserRepository;

import com.orders.user.responses.RegistrationResponse;
import com.orders.user.services.AdminService;
import com.orders.user.services.EmailService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;

/**
 * @author Ibney Ali
 */

@Slf4j
@Service
public class AdminServiceImpl implements AdminService {

	Logger logger = Logger.getLogger(AdminServiceImpl.class.getName());

	@Value("${password.reset.expire-time}")
	private String expirationTime;
	@Autowired
	UserRepository userRepository;
	@Autowired
	PasswordEncoder passwordEncoder;
	@Autowired
	AuthenticationManager authenticationManager;
	@Autowired
	RoleRepository roleRepository;
	@Autowired
	AuditLogRepository auditLogRepository;
	@Autowired
	PasswordResetTokenRepository passwordResetTokenRepository;
	@Autowired
	EmailService emailService;

	@Transactional
	public RegistrationResponse signup(RegisterUserDto input) {
		logger.info("Registering user: " + input);
		validatePassword(input.getPassword());
		if (usernameAlreadyExists(input.getUsername())) {
			logger.info("Username already exists: " + input.getUsername());
			throw new UserAlreadyExistsException("Username already exists.");
		}
		if (emailAlreadyExists(input.getEmail())) {
			logger.info("Email already exists: " + input.getEmail());
			throw new UserAlreadyExistsException("Email already exists.");
		}
		Role role = new Role();
		role.setCreatedAt(new Date());
		try {
			logger.info("Setting role: " + input.getRolename());
			role.setName(RoleName.valueOf(input.getRolename().toUpperCase()));
		} catch (IllegalArgumentException e) {
			throw new InvalidRoleException("Invalid role: " + input.getRolename());
		}
		role.setUpdatedAt(new Date());
		Role saveRole = roleRepository.save(role);
		User user = new User();
		user.setFullname(input.getFullname());
		user.setUsername(input.getUsername());
		user.setEmail(input.getEmail());
		user.setPassword(passwordEncoder.encode(input.getPassword()));
		user.setConfirmPassword(passwordEncoder.encode(input.getConfirmPassword()));
		user.setRole(saveRole);
		User returnUser = userRepository.save(user);

		RegistrationResponse response = new RegistrationResponse();
		response.setFullname(returnUser.getFullname());
		response.setUsername(returnUser.getUsername());
		response.setEmail(returnUser.getEmail());
		response.setRolename(returnUser.getRole().getName().toString());
		logger.info("User registered: " + response);
		return response;
	}

	@Transactional
	public User authenticate(LoginUserDto input) {
		logger.info("Authenticating user: " + input);
		validatePassword(input.getPassword());
		logger.info("Finding user with username or email: " + input.getUsername() + " " + input.getEmail());
		User user = findUserWithUsernameOrEmail(input.getUsername(), input.getEmail()).orElse(null);
		if (user != null) {
			logger.info("User found: " + user);
			if (!passwordEncoder.matches(input.getPassword(), user.getPassword())) {
				logger.info("Invalid credentials for user: " + user);
				throw new WrongCredentialsException("Invalid credentials");
			} else {
				logger.info("Authenticating user: " + user);
				authenticationManager
						.authenticate(new CustomEmailPasswordAuthenticationToken(user.getEmail(), input.getPassword()));
			}
		} else {
			logger.info("Invalid credentials");
			throw new WrongCredentialsException("Invalid credentials");
		}
		return user;
	}

	@Transactional
	public Map<String, String> forgotPassword(String email, HttpServletRequest request) {
		logger.info("Forgot password for email: " + email);
		validateEmail(email);
		Optional<User> userOptional = userRepository.findByEmail(email);
		logger.info("User found: " + userOptional);
		if (userOptional.isEmpty()) {
			logger.info("The provided email address does not match any account.");
			saveAuditLog(false, email);
			return Map.of("message", "The provided email address does not match any account.");
		}
		User user = userOptional.get();
		String token = JwtServiceImpl.generateToken();
		PasswordResetToken resetToken = new PasswordResetToken();
		resetToken.setToken(token);

		long expirationTimeInMillis = Long.parseLong(expirationTime);
		resetToken.setExpirationDate(new Date(System.currentTimeMillis() + expirationTimeInMillis));

		resetToken.setUser(user);
		passwordResetTokenRepository.save(resetToken);
		emailService.sendPasswordResetEmail(user.getEmail(), token);

		logger.info("Password reset link has been sent to your email address.");
		saveAuditLog(true, email);
		return Map.of("message", "Password reset link has been sent to your email address.");
	}

	private void validatePassword(String password) {
		logger.info("Validating password: " + password);
		if (password == null || password.length() < 8 ||
				!password.matches(".*[A-Z].*") ||
				!password.matches(".*[a-z].*") ||
				!password.matches(".*\\d.*") ||
				!password.matches(".*[!@#\\$%^&*(),.?\":{}|<>].*")) {
			logger.info("Password does not meet the required criteria");
			throw new InvalidPasswordException("Password does not meet the required criteria");
		}
	}

	private void validateEmail(String email) {
		if (email == null || !email.matches("^(?!\\.)[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+(?<!\\.)$")) {
			logger.info("Invalid email address");
			throw new InvalidEmailException("Invalid email address");
		}
	}
	private boolean usernameAlreadyExists(String username) {
		return userRepository.findByUsername(username).isPresent();
	}

	private boolean emailAlreadyExists(String email) {
		return userRepository.findByEmail(email).isPresent();
	}

	private Optional<User> findUserWithUsernameOrEmail(String username, String email) throws UsernameNotFoundException {
		Optional<User> user = userRepository.findByUsernameOrEmail(username, email);
		user.orElseThrow(() -> new EmailOrPasswordException("Email or Password is missing or invalid"));
		return user;
	}

	public User validatePasswordResetToken(String token) {
		PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token);
		logger.info("Validating password reset token: " + resetToken);
		if(resetToken == null) {
			throw new EmailOrPasswordException("Invalid token");
		}
		if (resetToken.getExpirationDate().before(new Date())) {
			throw new EmailOrPasswordException("Token has expired");
		}
		return resetToken.getUser();
	}

	@Transactional
	public void updatePassword(String token, String newPassword) {
		logger.info("Updating password for token: " + token);
		User user = validatePasswordResetToken(token);
		validatePassword(newPassword);
		user.setPassword(passwordEncoder.encode(newPassword));
		userRepository.save(user);
	}

	private void saveAuditLog(boolean status, String email){

		AuditLog aLog = new AuditLog();
		aLog.setEmail(email);
		if(!status){
			aLog.setAction("Password reset attempt for non-existent email");
		}else{
			aLog.setAction("Password reset requested");
		}
		aLog.setTimestamp(new Date());
		try {
			InetAddress inetAddress = InetAddress.getLocalHost();
			aLog.setIpAddress(inetAddress.getHostAddress());
		} catch (UnknownHostException e) {
			throw new CustomUnknownHostException("Failed to get host address", e);
		}
		auditLogRepository.save(aLog);
	}

	public void logout() {
		SecurityContextHolder.clearContext();
	}

}