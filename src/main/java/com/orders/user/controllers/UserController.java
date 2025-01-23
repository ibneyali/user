package com.orders.user.controllers;

import com.orders.user.entities.User;
import com.orders.user.exception.TokenExpiredException;
import com.orders.user.services.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Ibney Ali
 */

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private JwtService jwtService;

    @GetMapping("/userinfo")
    public ResponseEntity<User> authenticatedUser(@RequestHeader("Authorization") String authorizationHeader) {
        String token = authorizationHeader.replace("Bearer ", "");

        if (jwtService.isTokenExpired(token)) {
            throw new TokenExpiredException("Token has expired");
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = (User) authentication.getPrincipal();
        return ResponseEntity.ok(currentUser);
    }

    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("Test");
    }
}
