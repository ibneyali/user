package com.orders.user.config;

import com.orders.user.entities.User;
import com.orders.user.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class CustomEmailPasswordAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String email = authentication.getName();
        String password = (String) authentication.getCredentials();

        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty() || !passwordEncoder.matches(password, userOptional.get().getPassword())) {
            throw new BadCredentialsException("Invalid email or password");
        }

        User user = userOptional.get();
        return new CustomEmailPasswordAuthenticationToken(user.getEmail(), password, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomEmailPasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}