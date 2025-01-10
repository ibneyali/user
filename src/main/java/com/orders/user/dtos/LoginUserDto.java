package com.orders.user.dtos;

public class LoginUserDto {
	private String username;
	private String email;
	private String password;

	public String getUsername() {
		return username;
	}

	public LoginUserDto setUsername(String username) {
		this.username = username;
		return this;
	}

	public String getEmail() {
		return email;
	}

	public LoginUserDto setEmail(String email) {
		this.email = email;
		return this;
	}

	public String getPassword() {
		return password;
	}

	public LoginUserDto setPassword(String password) {
		this.password = password;
		return this;
	}

	@Override
	public String toString() {
		return "LoginUserDto{" + "username='" + username + '\'' + "email='" + email + '\'' + ", password='" + password
				+ '\'' + '}';
	}
}