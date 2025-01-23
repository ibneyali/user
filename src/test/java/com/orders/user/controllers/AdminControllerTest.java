package com.orders.user.controllers;

import com.orders.user.dto.LoginUserDto;
import com.orders.user.dto.RegisterUserDto;
import com.orders.user.dto.UpdatePasswordDto;
import com.orders.user.entities.User;
import com.orders.user.exception.EmailOrPasswordException;
import com.orders.user.exception.UserAlreadyExistsException;
import com.orders.user.responses.LoginResponse;
import com.orders.user.responses.RegistrationResponse;
import com.orders.user.services.AdminService;
import com.orders.user.services.impl.JwtServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class AdminControllerTest {

    Logger log = Logger.getLogger(AdminController.class.getName());

    @Mock
    private JwtServiceImpl jwtService;

    @Mock
    private AdminService adminService;

    @InjectMocks
    private AdminController adminController;

    @Mock
    private UserDetails userDetails;


    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testRegister_Success() {
        RegisterUserDto registerUserDto = new RegisterUserDto();
        RegistrationResponse registrationResponse = new RegistrationResponse();
        when(adminService.signup(any(RegisterUserDto.class))).thenReturn(registrationResponse);

        ResponseEntity<RegistrationResponse> response = adminController.register(registerUserDto);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(registrationResponse, response.getBody());
    }

    @Test
    public void testLoginWithCred_Success() throws UserAlreadyExistsException {
        LoginUserDto loginUserDto = new LoginUserDto();
        User user = new User();
        String token = "jwtToken";
        when(adminService.authenticate(any(LoginUserDto.class))).thenReturn(user);
        when(jwtService.generateToken(any(User.class))).thenReturn(token);
        when(jwtService.getExpirationTime()).thenReturn(3600L);

        ResponseEntity<LoginResponse> response = adminController.loginWithCred(loginUserDto);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Login successful.", response.getBody().getSuccessMessage());
        assertEquals(token, response.getBody().getToken());
    }

    @Test
    public void testLoginWithCred_UserAlreadyExistsException() throws UserAlreadyExistsException {
        LoginUserDto loginUserDto = new LoginUserDto();
        when(adminService.authenticate(any(LoginUserDto.class))).thenThrow(new UserAlreadyExistsException(null));

        ResponseEntity<LoginResponse> response = adminController.loginWithCred(loginUserDto);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
    }

    @Test
    public void testForgotPassword_Success() {
        String email = "test@gmail.com";
        HttpServletRequest request = mock(HttpServletRequest.class);
        Map<String, String> responseMap = new HashMap<>();
        when(adminService.forgotPassword(anyString(), any(HttpServletRequest.class))).thenReturn(responseMap);

        ResponseEntity<Map<String, String>> response = adminController.forgotPassword(email, request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(responseMap, response.getBody());
    }

    @Test
    public void testResetPassword_Success() throws EmailOrPasswordException {
        String token = "validToken";
        User user = new User();
        user.setUsername("testUser");
        when(adminService.validatePasswordResetToken(anyString())).thenReturn(user);

        ResponseEntity<String> response = adminController.resetPassword(token);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Password reset token is valid. User: testUser", response.getBody());
    }

    @Test
    public void testResetPassword_InvalidToken() throws EmailOrPasswordException {
        String token = "invalidToken";
        when(adminService.validatePasswordResetToken(anyString())).thenThrow(new EmailOrPasswordException(token));
        ResponseEntity<String> response = adminController.resetPassword(token);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Invalid token", response.getBody());
    }

    @Test
    public void testUpdatePassword_Success() throws EmailOrPasswordException {
        UpdatePasswordDto updatePasswordDto = new UpdatePasswordDto();
        updatePasswordDto.setToken("validToken");
        updatePasswordDto.setNewPassword("newPassword");

        ResponseEntity<String> response = adminController.updatePassword(updatePasswordDto);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Password updated successfully.", response.getBody());
    }

    @Test
    public void testUpdatePassword_InvalidTokenOrPassword() throws EmailOrPasswordException {
        UpdatePasswordDto updatePasswordDto = new UpdatePasswordDto();
        updatePasswordDto.setToken("invalidToken");
        updatePasswordDto.setNewPassword("newPassword");
        doThrow(new EmailOrPasswordException(null)).when(adminService).updatePassword(anyString(), anyString());

        ResponseEntity<String> response = adminController.updatePassword(updatePasswordDto);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Invalid token or password.", response.getBody());
    }
}
