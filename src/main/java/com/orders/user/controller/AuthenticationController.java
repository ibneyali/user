package com.orders.user.controller;

import com.orders.user.entities.User;
import com.orders.user.exception.UserAlreadyExistsException;
import com.orders.user.dtos.LoginUserDto;
import com.orders.user.dtos.RegisterUserDto;
import com.orders.user.responses.LoginResponse;
import com.orders.user.services.AuthenticationService;
import com.orders.user.services.JwtService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {
	private final JwtService jwtService;
	private final AuthenticationService authenticationService;

	public AuthenticationController(JwtService jwtService, AuthenticationService authenticationService) {
		this.jwtService = jwtService;
		this.authenticationService = authenticationService;
	}

	@PostMapping("/registration")
	public ResponseEntity<User> register(@RequestBody RegisterUserDto registerUserDto) {
		User registeredUser = authenticationService.signup(registerUserDto);

		return ResponseEntity.ok(registeredUser);
	}

	@PostMapping("/login")
	public ResponseEntity<LoginResponse> authenticate(@RequestBody LoginUserDto loginUserDto) {
		try {
			User authenticatedUser = authenticationService.authenticate(loginUserDto);

			String jwtToken = jwtService.generateToken(authenticatedUser);

			LoginResponse loginResponse = new LoginResponse().setToken(jwtToken)
					.setExpiresIn(jwtService.getExpirationTime());

			return ResponseEntity.ok(loginResponse);
		} catch (UserAlreadyExistsException e) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body(null);
		}
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout() {
		authenticationService.logout();
		return ResponseEntity.ok().build();
	}
}