package com.spring_security.jwt_token_complete.jwt_config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.spring_security.jwt_token_complete.service.JwtService;
import com.spring_security.jwt_token_complete.service.MyUserDetailService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter{
    
    @Autowired
    private JwtService jwtService;

    @Autowired
    private MyUserDetailService myUserDetailService;

    /*
     * Questa funzione andrà a controllare il token prendendolo, partendo da dopo lo
     * spazio della parola Bearer
     * dopo di che estrarrà l'username dal token per vedere se è autorizzato e se
     * l'username è effettivamente presente
     * successivamente andrà ad utilizzare l'username verificato all'interno del
     * metodo loadUserByUsername mettendo
     * tutti i dettagli dell'utente nella variabile userDetails.
     * 
     * Dopo aver verificato la validità del token verrà creato un token di
     * autenticazione usando l'user e la password
     * in questa riga di codice : UsernamePasswordAuthenticationToken
     * quindi in fine verrà segnato come loggato
     * 
     * mentre a questo punto del codice: authenticationToken.setDetails
     * controlliamo i dettagli del client che sta effettuando questa richiesta
     * 
     * Alla fine di tutto il metodo facciamo partire la catena di filtri
     * filterChain.doFilter(request, response); che filtrerà quindi
     * la richiesta e la risposta.
     * 
     * IN SINTESI è LA FUNZIONE CHE CONTROLLA I DATI INCLUSI NEL TOKEN DANDO 
     * ACCESSO O MENO AGLI ANDPOINT
     */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws 
        ServletException, IOException {

            // Escludi la rotta di login e altre rotte pubbliche dal filtro JWT
            String requestPath = request.getServletPath();
            if (requestPath.equals("/api/content/authenticate")
                    || requestPath.equals("/api/registerController/register/new-user")
                    || requestPath.equals("/api/content/home")) {
                filterChain.doFilter(request, response);
                return;
            }

            String authHeader = request.getHeader("Authorization");

            if ( authHeader == null || !authHeader.startsWith("Bearer ")){
                // Se l'header Authorization è mancante o non inizia con "Bearer", restituisci
                // 401 Unauthorized
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Error: Unauthorized - No token provided");
                return;
            }

            String jwt = authHeader.substring(7);
            String username = jwtService.extractUsername(jwt);

            if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
                UserDetails userDetails = myUserDetailService.loadUserByUsername(username);

                if(userDetails != null && jwtService.isTokenValid(jwt)){
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        username, 
                        userDetails.getPassword(),
                        userDetails.getAuthorities()
                        );

                        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                } else {
                    // Se il token non è valido, restituisci 401 Unauthorized
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Error: Unauthorized - Invalid token");
                    return;
                }
            }
            filterChain.doFilter(request, response); 
        }
}
