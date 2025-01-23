package com.orders.user.responses;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * @author Ibney Ali
 */

@ToString
@Getter
@Setter
public class RegistrationResponse {

	private String fullname;
	private String username;
	private String email;
	private String password;
	private String rolename;

}