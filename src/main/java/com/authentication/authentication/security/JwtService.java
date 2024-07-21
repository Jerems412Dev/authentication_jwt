package com.authentication.authentication.security;

import com.authentication.authentication.dto.UserDTO;
import com.authentication.authentication.entity.ApiToken;
import com.authentication.authentication.entity.UserEntity;
import com.authentication.authentication.mapper.UserMapper;
import com.authentication.authentication.repository.ApiTokenRepository;
import com.authentication.authentication.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

@Component
public class JwtService {
    @Autowired
    private UserMapper userMapper;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ApiTokenRepository apitokenRepository;

    // Secret Key for signing the JWT. It should be kept private.
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    // Generates a JWT token for the given userName.
    public String generateToken(UserDTO user) {
        // Prepare claims for the token
        Map<String, Object> claims = new HashMap<>();
        Optional<UserEntity> userClaim = userRepository.findByUsername(user.getUsername());
        UserDTO userDTO = new UserDTO();
        if (userClaim.isPresent()) {
            userDTO = userMapper.toUserDTO(userClaim.get());
        }
        claims.put("idUser", userDTO.getIdUser());
        claims.put("isValid", true);
        // Build JWT token with claims, subject, issued time, expiration time, and signing algorithm
        // Token valid for 90 minutes
        var token = Jwts.builder()
                .setClaims(claims)
                .setSubject(userDTO.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 90))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
        ApiToken apitoken = new ApiToken();
        if(Boolean.FALSE.equals(apitokenRepository.existsByUsername(userDTO.getUsername()))) {
            apitoken.setToken(token);
            apitoken.setCreatedAt(extractIssuedAt(token));
            apitoken.setUpdatedAt(new Date(System.currentTimeMillis()));
            apitoken.setIsValid(true);
            apitoken.setUsername(userDTO.getUsername());
        }else {
            apitoken = apitokenRepository.findByUsername(userDTO.getUsername());
            apitoken.setToken(token);
            apitoken.setIsValid(true);
            apitoken.setUpdatedAt(new Date(System.currentTimeMillis()));
        }
        apitokenRepository.save(apitoken);
        return token;
    }

    // Creates a signing key from the base64 encoded secret.
    //returns a Key object for signing the JWT.
    private Key getSignKey() {
        // Decode the base64 encoded secret key and return a Key object
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }


    // Extracts the userName from the JWT token.
    //return -> The userName contained in the token.
    public String extractUserName(String token) {
        // Extract and return the subject claim from the token
        return extractClaim(token, Claims::getSubject);
    }

    // Extracts the valid from the JWT token.
    //return -> The valid contained in the token.
    public Boolean extractIsValid(String token) {
        final Claims claims = extractAllClaims(token);
        return claims != null && (Boolean) claims.get("isValid");
    }


    // Extracts the expiration date from the JWT token.
    //@return The expiration date of the token.
    public Date extractExpiration(String token) {
        // Extract and return the expiration claim from the token
        return extractClaim(token, Claims::getExpiration);
    }

    // Extracts the issuesAt date from the JWT token.
    //@return The expiration date of the token.
    public Date extractIssuedAt(String token) {
        // Extract and return the expiration claim from the token
        return extractClaim(token, Claims::getIssuedAt);
    }


    // Extracts a specific claim from the JWT token.
    // claimResolver A function to extract the claim.
    // return-> The value of the specified claim.
    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        // Extract the specified claim using the provided function
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    //Extracts all claims from the JWT token.
    //return-> Claims object containing all claims.
    private Claims extractAllClaims(String token) {
        // Parse and return all claims from the token
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build().parseClaimsJws(token).getBody();
    }


    //Checks if the JWT token is expired.
    //return-> True if the token is expired, false otherwise.
    public Boolean isTokenExpired(String token) {
        // Check if the token's expiration time is before the current time
        return extractExpiration(token).before(new Date());
    }

    //Validates the JWT token against the UserDetails.
    //return-> True if the token is valid, false otherwise.

    public Boolean validateToken(String token, UserDetails userDetails) {
        // Extract username from token and check if it matches UserDetails' username
        final String userName = extractUserName(token);
        // Also check if the token is valid
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token) && apitokenRepository.existsByTokenAndIsValid(token,true));
    }
}