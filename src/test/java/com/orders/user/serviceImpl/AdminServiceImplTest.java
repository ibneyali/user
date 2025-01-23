package com.orders.user.serviceImpl;

import com.orders.user.config.CustomEmailPasswordAuthenticationToken;
import com.orders.user.entities.AuditLog;
import com.orders.user.entities.PasswordResetToken;
import com.orders.user.entities.Role;
import com.orders.user.enums.RoleName;
import com.orders.user.entities.User;
import com.orders.user.repositories.AuditLogRepository;
import com.orders.user.repositories.PasswordResetTokenRepository;
import com.orders.user.repositories.RoleRepository;
import com.orders.user.repositories.UserRepository;
import com.orders.user.services.EmailService;
import com.orders.user.services.JwtService;
import com.orders.user.services.impl.AdminServiceImpl;
import com.orders.user.services.impl.JwtServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Date;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class AdminServiceImplTest {

    @Autowired
    EmailService emailService;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AdminServiceImpl adminService;

    @Autowired
    AuditLogRepository auditLogRepository;

    @BeforeAll
    public static void setUp(@Autowired RoleRepository roleRepository, @Autowired UserRepository userRepository, @Autowired PasswordEncoder passwordEncoder) {
        MockitoAnnotations.openMocks(AdminServiceImplTest.class);

        Role role = new Role();
        role.setName(RoleName.SUPER_ADMIN);
        role.setCreatedAt(new Date());
        role.setUpdatedAt(new Date());
        role = roleRepository.save(role);

        User user = new User();
        user.setFullname("TestName");
        user.setUsername("testUser");
        user.setEmail("test@example.com");

        String encodedPassword = passwordEncoder.encode("Test!User1");
        user.setPassword(encodedPassword);
        user.setRole(role);
        User returnUser = userRepository.save(user);
        System.out.println(returnUser);

        // To decode and verify the password
        boolean isPasswordMatch = passwordEncoder.matches("Test!User1", returnUser.getPassword());
        System.out.println("Password matches: " + isPasswordMatch);
    }

    @Test
    public void testDummyUserExists() {
        User user = userRepository.findByUsername("testUser").orElse(null);
        System.out.println(user);
        assertNotNull(user);
    }

    @Test
    public void testAuthenticate_Success() {
        //Email and password both are correct
        User u = new User();
        u.setEmail("test@example.com");
        u.setPassword(passwordEncoder.encode("Test!User1"));

        User user =  userRepository.findByUsernameOrEmail("test@example.com", "test@example.com").orElse(null);
        System.out.println(user);

        assert user != null;
        assertTrue(passwordEncoder.matches("Test!User1", user.getPassword()));
        assertNotNull(authenticationManager
                .authenticate(new CustomEmailPasswordAuthenticationToken(user.getEmail(), "Test!User1")));

    }


    @Test
    public void testAuthenticate_InvalidCredentials() {

        //Email is correct but password is wrong - Throw bad credentials
        User u = new User();
        u.setEmail("test@example.com");
        u.setPassword(passwordEncoder.encode("Test!User11"));

        User user =  userRepository.findByUsernameOrEmail("test@example.com", "test@example.com").orElse(null);
        System.out.println(user);

        assert user != null;
        assertFalse(passwordEncoder.matches("Test!User11", user.getPassword()));
        assertThrows(BadCredentialsException.class, () -> {
            authenticationManager.authenticate(new CustomEmailPasswordAuthenticationToken(user.getEmail(), "Test!User11"));
        });
    }

    @Test
    public void forgotPasswordTest() {
        String email = "test@example.com";
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRemoteAddr()).thenReturn("127.0.0.1");

        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isEmpty()) {
            AuditLog aLog = new AuditLog();
            aLog.setEmail(email);
            aLog.setAction("Password reset attempt for non-existent email");
            aLog.setTimestamp(new Date());
            aLog.setIpAddress(request.getRemoteAddr());
            AuditLog saveaLog = auditLogRepository.save(aLog);
            assertEquals("The provided email address does not match any account.", Map.of("message", "The provided email address does not match any account.").get("message"));
        } else {
            User user = userOptional.get();
            String token = JwtServiceImpl.generateToken();
            PasswordResetToken resetToken = new PasswordResetToken();
            resetToken.setToken(token);
            String expirationTime = "900000";
            long expirationTimeInMillis = Long.parseLong(expirationTime);
            resetToken.setExpirationDate(new Date(System.currentTimeMillis() + expirationTimeInMillis));

            resetToken.setUser(user);
            passwordResetTokenRepository.save(resetToken);

            emailService.sendPasswordResetEmail(user.getEmail(), token);
            AuditLog log = new AuditLog();
            log.setEmail(user.getEmail());
            log.setAction("Password reset requested");
            log.setTimestamp(new Date());
            log.setIpAddress(request.getRemoteAddr());
            auditLogRepository.save(log);

            assertEquals("Password reset link has been sent to your email address.", Map.of("message", "Password reset link has been sent to your email address.").get("message"));
        }
    }

    @Test
    public void validatePasswordResetTokenTest() {

        User user = userRepository.findByEmail("test@example.com").orElse(null);
        String token = JwtServiceImpl.generateToken();

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setToken(token);
        String expirationTime = "900000";
        long expirationTimeInMillis = Long.parseLong(expirationTime);
        resetToken.setExpirationDate(new Date(System.currentTimeMillis() + expirationTimeInMillis));

        resetToken.setUser(user);
        passwordResetTokenRepository.save(resetToken);

        PasswordResetToken pResetToken = passwordResetTokenRepository.findByToken(token);

        assertNotNull(pResetToken);
        assertEquals(token, pResetToken.getToken());
    }
}