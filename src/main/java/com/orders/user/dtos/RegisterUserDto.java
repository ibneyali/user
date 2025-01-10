package com.orders.user.dtos;

public class RegisterUserDto {
	private String email;
	private String username;
	private String password;
	private String confirmPassword;
	private String fullName;

	public String getEmail() {
		return email;
	}

	public RegisterUserDto setEmail(String email) {
		this.email = email;
		return this;
	}

	public String getUsername() {
		return username;
	}

	public RegisterUserDto setUsername(String username) {
		this.username = username;
		return this;
	}

	public String getPassword() {
		return password;
	}

	public RegisterUserDto setPassword(String password) {
		this.password = password;
		return this;
	}

	public String getConfirmPassword() {
		return confirmPassword;
	}

	public RegisterUserDto setConfirmPassword(String confirmPassword) {
		this.confirmPassword = confirmPassword;
		return this;
	}

	public String getFullName() {
		return fullName;
	}

	public RegisterUserDto setFullName(String fullName) {
		this.fullName = fullName;
		return this;
	}

	@Override
	public String toString() {
		return "RegisterUserDto{" + "email='" + email + '\'' + ", username='" + username + '\'' + ", password='"
				+ password + '\'' + ", confirmPassword='" + confirmPassword + '\'' + ", fullName='" + fullName + '\''
				+ '}';
	}
}