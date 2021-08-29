package com.example.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {

    //metoda rozszyfrująca zaszyfrowane hasła
    @Bean
    public PasswordEncoder passwordEncoder() {
        //najczęściej używany koder hasła (BCryptPasswordEncoder
        return new BCryptPasswordEncoder(10);
    }
}
