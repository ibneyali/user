package com.orders.user.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * @author Ibney Ali
 */

@Getter
@Setter
public class UpdatePasswordDto {

    private String token;
    private String password;
    private String confirmPassword;

}
