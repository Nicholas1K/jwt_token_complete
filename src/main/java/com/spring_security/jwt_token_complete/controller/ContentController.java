package com.spring_security.jwt_token_complete.controller;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.RestController;

import com.spring_security.jwt_token_complete.model.AuthResponse;
import com.spring_security.jwt_token_complete.model.LoginForm;
import com.spring_security.jwt_token_complete.service.JwtService;
import com.spring_security.jwt_token_complete.service.MyUserDetailService;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

/* questa classe principalmente serve per l'autenticazione dell'utente */


@RestController
@CrossOrigin
@RequestMapping("api/content")
public class ContentController {
    
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private MyUserDetailService myUserDetailService;

    @GetMapping("/home")
    public String handleWelcome() {
        return "Welcome to home!";
    }
    
    @GetMapping("/admin/home")
    public String handleAdminHome() {
        return "Welcome to ADMIN home!";
    }

    @GetMapping("/user/home")
    public String handleUserHome() {
        return "Welcome to USER home!";
    }

    /* QUESTA è IL METODO DELLA LOGIN PER ACCEDERE CHE RESTITUISCE IL TOKEN DELL'UTENTE SE ESISTE NEL SISTEMA*/

    @PostMapping("/authenticate")
    public AuthResponse authenticateAndGetToken(@RequestBody LoginForm loginForm) {

        // Autentica l'utente con username e password
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
            loginForm.username(), loginForm.password()));

            // Se l'autenticazione è valida
            if (authentication.isAuthenticated()){

                //ottengo i dettagli dell'utente
                UserDetails userDetails = myUserDetailService.loadUserByUsername(loginForm.username());

                //Genero il token
                String token = jwtService.generateToken(userDetails);

                //ottengo il ruolo o la lista dei ruoli
                List<String> roles = userDetails.getAuthorities().stream()
                                        .map(GrantedAuthority::getAuthority)
                                        .collect(Collectors.toList());

                //restituisco il token e i ruoli
                return new AuthResponse(token,roles);

            } else {
                throw new UsernameNotFoundException("Invalid credentials");
            }
    }
    
}
