package com.orders.user.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * @author Ibney Ali
 */

@Getter
@Setter
@ToString
public class LoginUserDto {
	private String identifier;
	private String password;
}