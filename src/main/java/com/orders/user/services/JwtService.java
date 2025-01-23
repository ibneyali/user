package com.orders.user.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;
import java.util.function.Function;

/**
 * @author Ibney Ali
 */

public interface JwtService {

    public String extractUsername(String token);
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) ;
    public String generateToken(UserDetails userDetails);
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails);
    public long getExpirationTime();
    public boolean isTokenValid(String token, UserDetails userDetails);
    public boolean isTokenExpired(String token);
}
