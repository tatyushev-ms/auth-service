package com.efa.security.oauth2.provider.code;

import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;

/**
 * Services for issuing and storing authorization codes, takes over
 * from {@link org.springframework.security.oauth2.provider.code.AuthorizationCodeServices}.
 */
public interface ExtendedAuthorizationCodeServices {
    
    /**
     * Create an authorization code for the specified authentications.
     *
     * @param authentication The authentications to use.
     * @return The generated code.
     */
    String createAuthorizationCode(OAuth2Authentication authentication);
    
    /**
     * Consume a token request.
     *
     * @param tokenRequest The token request to consume.
     * @return The authentications associated with the token request.
     * @throws InvalidGrantException If the token request is invalid.
     */
    OAuth2Authentication consumeTokenRequest(TokenRequest tokenRequest) throws InvalidGrantException;
    
}
