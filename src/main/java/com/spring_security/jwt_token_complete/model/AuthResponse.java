package com.spring_security.jwt_token_complete.model;

import java.util.List;

/* 
 * QUESTA è LA CLASSE CHE VERRà USATA DAL METODO authenticateAndGetToken DELLA CLASSE CONTENTCONTROLLER.JAVA
 * IN MODO CHE LA CHIAMATA CHE FARà LA LOGIN MI RITORNERà UN ARRAY CONTENTENTE UN TOKEN E LA LISTA DEI RUOLI DELL'UTENETE
 * 
 * IN SINTESI è UNA CLASSE CHE FUNGE COME CONTENITORE O ISTRUZIONE PER FARMI RITORNARE DEI DATI UNA VOLTA CHE 
 * HO ESEGUITO LA CHIAMATA POST PER LA LOGIN
 */
public class AuthResponse {
    
    private String token;

    private List<String> roles;

    public AuthResponse(String token, List<String> roles) {
        this.token = token;
        this.roles = roles;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    
}
