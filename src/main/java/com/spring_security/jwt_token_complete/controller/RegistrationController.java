package com.spring_security.jwt_token_complete.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RestController;

import com.spring_security.jwt_token_complete.model.MyUser;
import com.spring_security.jwt_token_complete.repository.MyUserRepository;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;


@RestController
@CrossOrigin
@RequestMapping("/api/registerController")
public class RegistrationController {

     @Autowired
     private MyUserRepository myUserRepository;

     @Autowired
     private PasswordEncoder passwordEncoder;

     @PostMapping("/register/new-user")
     public MyUser createUser(@RequestBody MyUser user) {
         user.setPassword(passwordEncoder.encode(user.getPassword()));
         return myUserRepository.save(user);
     }
     
}
