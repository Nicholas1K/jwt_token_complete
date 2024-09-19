package com.spring_security.jwt_token_complete.service;

import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
    
    private static final String SECRET = "638CBE3A90E0303BF3808F40F95A7F02A24B4B5D029C954CF553F79E9EF1DC0384BE681C249F1223F6B55AA21DC070914834CA22C8DD98E14A872CA010091ACC";
    private static final long VALIDITY = TimeUnit.DAYS.toMillis(1);

    private SecretKey generateKey() {
        byte[] decodedKey = Base64.getDecoder().decode(SECRET);
        return Keys.hmacShaKeyFor(decodedKey);
    }

    /*
     * in questo metodo genero il token il token può essere formato da diverse variabili
     * attualmente in questa funzione viene utilizzata solamente quella di un host
     * ma potremmo aggiungere un nome e una password e tutte le info che desidero
     * in questo modo : 
     * claims.put("name","nico");
     * claims.put("password","12huyuy3ti");
     * e così via
    */

    public String generateToken(UserDetails userDetails){
        Map<String, String> claims = new HashMap<>();
        claims.put("iss", "https://secure.genuinecoder.com");
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(VALIDITY)))
                .signWith(generateKey())
                .compact();
    }

    /*METODO CHE LEGGE LE INFORMAZIONI ALL'INTERNO DEL TOKEN */
    
    public Claims getClaims(String jwt){
        return Jwts.parser()
                .verifyWith(generateKey())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    public String extractUsername(String jwt){
        Claims claims = getClaims(jwt);
        return claims.getSubject();
    }

    public boolean isTokenValid(String jwt){
        Claims claims = getClaims(jwt);
        return claims.getExpiration().after(Date.from(Instant.now()));
    }
}
