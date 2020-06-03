package com.efa.security.oauth2.provider.code;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Basic interface for issuing authorization codes.
 */
public interface AuthorizationCodeGenerator {
    
    /**
     * Create an authorization code for the specified authentications.
     *
     * @param authentication The authentications to use.
     * @return The generated code.
     */
    String createAuthorizationCode(OAuth2Authentication authentication);
    
}
