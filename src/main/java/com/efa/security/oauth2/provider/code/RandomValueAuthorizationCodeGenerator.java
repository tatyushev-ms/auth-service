package com.efa.security.oauth2.provider.code;

import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Implementation for an authorization code generator that generates a random-value authorization code.
 */
public class RandomValueAuthorizationCodeGenerator implements AuthorizationCodeGenerator {
    
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    
    @Override
    public String createAuthorizationCode(OAuth2Authentication authentication) {
        return generator.generate();
    }
    
}
