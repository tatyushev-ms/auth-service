package com.efa.security.oauth2.provider.code;

import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;

/**
 * Adapter that implements a Spring {@link AuthorizationCodeServices, delegating to
 * an {@link ExtendedAuthorizationCodeServices} underneath.
 * It is used in {@link org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint}.
 */
@AllArgsConstructor
public class ExtendedAuthorizationCodeServicesAdapter implements AuthorizationCodeServices {
    
    private final ExtendedAuthorizationCodeServices extendedAuthorizationCodeServices;
    
    @Override
    public String createAuthorizationCode(OAuth2Authentication authentication) {
        return extendedAuthorizationCodeServices.createAuthorizationCode(authentication);
    }
    
    @Override
    public OAuth2Authentication consumeAuthorizationCode(String code) {
        throw new UnsupportedOperationException();
    }
    
}
