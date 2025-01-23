package com.orders.user.exception;

/**
 * @author Ibney Ali
 */

public class UserAlreadyExistsException extends RuntimeException {
	public UserAlreadyExistsException(String message) {
		super(message);
	}
}