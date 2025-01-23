package com.orders.user.responses;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * @author Ibney Ali
 */

@Getter
@Setter
@ToString
public class LoginResponse {
	private String token;
	private long expiresIn;
	private String successMessage;
}