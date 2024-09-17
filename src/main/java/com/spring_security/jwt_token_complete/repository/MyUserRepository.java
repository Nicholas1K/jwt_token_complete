package com.spring_security.jwt_token_complete.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.spring_security.jwt_token_complete.model.MyUser;


public interface MyUserRepository extends JpaRepository<MyUser,Long> {
    
    Optional<MyUser> findByUsername(String username);
}
