package com.orders.user.exception;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.net.UnknownHostException;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class CustomUnknownHostException extends RuntimeException {
    public CustomUnknownHostException(String message, UnknownHostException e) {
        super(message);
    }
}