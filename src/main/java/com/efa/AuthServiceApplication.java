package com.efa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

//@EnableDiscoveryClient
@SpringBootApplication
public class AuthServiceApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
    
    @Bean
    public PasswordEncoder userDetailsServicePasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public PasswordEncoder clientDetailsServicePasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
}
