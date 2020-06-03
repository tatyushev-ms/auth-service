package com.efa.security.oauth2.provider.code;

import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CODE;

/**
 * Base implementation for extended authorization code services that introduce generation and storing of authorization codes.
 */
@AllArgsConstructor
public abstract class AbstractExtendedAuthorizationCodeServices<S extends AuthorizationCodeStoreItem<OAuth2Authentication>>
        implements ExtendedAuthorizationCodeServices {
    
    private final AuthorizationCodeGenerator authorizationCodeGenerator;
    private final AuthorizationCodeStore<OAuth2Authentication, S> authorizationCodeStore;
    
    @Override
    public String createAuthorizationCode(OAuth2Authentication authentication) {
        final S storeItem = makeStoreItem(authentication);
        final String authorizationCode = authorizationCodeGenerator.createAuthorizationCode(authentication);
        authorizationCodeStore.store(authorizationCode, storeItem);
        return authorizationCode;
    }
    
    protected abstract S makeStoreItem(OAuth2Authentication authentication);
    
    @Override
    public OAuth2Authentication consumeTokenRequest(TokenRequest tokenRequest) throws InvalidGrantException {
        final String authorizationCode = tokenRequest.getRequestParameters().get(CODE);
        if (authorizationCode == null) {
            throw new InvalidRequestException("An authorization code must be supplied.");
        }
        final S storeItem = authorizationCodeStore.get(authorizationCode);
        if (storeItem == null) {
            throw new InvalidGrantException("Invalid authorization code: " + authorizationCode);
        }
        verify(storeItem, tokenRequest);
        return storeItem.get();
    }
    
    protected abstract void verify(S storeItem, TokenRequest tokenRequest);
    
}
