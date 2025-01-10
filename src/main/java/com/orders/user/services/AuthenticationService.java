package com.orders.user.services;

import com.orders.user.dtos.LoginUserDto;
import com.orders.user.dtos.RegisterUserDto;
import com.orders.user.entities.User;
import com.orders.user.exception.PasswordMismatchException;
import com.orders.user.exception.UserAlreadyExistsException;
import com.orders.user.repositories.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class AuthenticationService implements UserDetailsService {
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final UserDetailsService userDetailsService;

	public AuthenticationService(UserRepository userRepository, AuthenticationManager authenticationManager,
			PasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
		this.authenticationManager = authenticationManager;
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.userDetailsService = userDetailsService;
	}

	public User signup(RegisterUserDto input) {
		if (userExists(input.getUsername(), input.getEmail())) {
			throw new UserAlreadyExistsException("User with this username or email already exists.");
		}

		if (!input.getPassword().equals(input.getConfirmPassword())) {
			throw new PasswordMismatchException("Password and confirm password do not match.");
		}
		var user = new User();
		user.setFullName(input.getFullName());
		user.setUsername(input.getUsername());
		user.setEmail(input.getEmail());
		user.setPassword(passwordEncoder.encode(input.getPassword()));
		user.setConfirmPassword(passwordEncoder.encode(input.getConfirmPassword()));

		return userRepository.save(user);
	}

	public User authenticate(LoginUserDto input) {
		UserDetails userDetails;
		Optional<User> userOptional = userRepository.findByEmail(input.getEmail());
		if (userOptional.isPresent()) {
			userDetails = userDetailsService.loadUserByUsername(userOptional.get().getEmail());
		} else {
			userOptional = userRepository.findByUsername(input.getUsername());
			if (userOptional.isPresent()) {
				userDetails = userDetailsService.loadUserByUsername(userOptional.get().getUsername());
			} else {
				throw new BadCredentialsException("Bad credentials");
			}
		}

		if (!passwordEncoder.matches(input.getPassword(), userDetails.getPassword())) {
			throw new BadCredentialsException("Bad credentials");
		}

		authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(userDetails.getUsername(), input.getPassword()));

		return userOptional.orElseThrow(() -> new RuntimeException("User not found"));
	}

	public List<User> allUsers() {
		List<User> users = new ArrayList<>();

		userRepository.findAll().forEach(users::add);

		return users;
	}

	private boolean userExists(String username, String email) {
		return userRepository.findByUsernameOrEmail(username, email).isPresent();
	}

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		User user = userRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
		return org.springframework.security.core.userdetails.User.builder().username(user.getEmail())
				.password(user.getPassword()).authorities("USER").build();
	}

	public void logout() {
		SecurityContextHolder.clearContext();
	}
}