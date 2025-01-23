package com.orders.user.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * @author Ibney Ali
 */

@ToString
@Getter
@Setter
public class RegisterUserDto {

	private String fullname;
	private String username;
	private String email;
	private String rolename;
	private String password;
	private String confirmPassword;
}