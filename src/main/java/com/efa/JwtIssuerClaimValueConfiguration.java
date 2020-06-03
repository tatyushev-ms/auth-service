package com.efa;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.net.MalformedURLException;
import java.net.URL;

@Configuration
public class JwtIssuerClaimValueConfiguration {
    
    @Profile("with-simple-iss")
    @Bean
    public URL jwtIssuerClaimValue(@Value("${server.port}") int port, @Value("${server.servlet.context-path:}") String contextPath) throws MalformedURLException {
        final String baseUrl = String.format("%s://%s:%d%s", "http", "localhost", port, contextPath);
        return new URL(baseUrl);
    }
    
}
