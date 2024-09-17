package com.spring_security.jwt_token_complete.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.spring_security.jwt_token_complete.model.MyUser;
import com.spring_security.jwt_token_complete.repository.MyUserRepository;

@Service
public class MyUserDetailService implements UserDetailsService{
    
    @Autowired
    private MyUserRepository repository;

    /* QUESTO METODO VIENE UTILIZZATO PER  L'AUTENTICAZIONE IN CONTENTCONTROLLER.JAVA PER CERCARE L'UTENTE TRAMITE USERNAME E LOGGARLO*/
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<MyUser> user = repository.findByUsername(username);
        if (user.isPresent()){
            var userObj = user.get();
            return User.builder()
                    .username(userObj.getUsername())
                    .password(userObj.getPassword())
                    .roles(getRoles(userObj))
                    .build();
        } else {
            throw new UsernameNotFoundException(username);
        }
    }

    private String[] getRoles(MyUser user) {
        if (user.getRole() == null){
            return new String[]{"USER"};
        }
        return user.getRole().split(",");
    }
}
