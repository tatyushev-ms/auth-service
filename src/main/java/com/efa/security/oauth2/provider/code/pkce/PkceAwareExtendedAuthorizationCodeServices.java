package com.efa.security.oauth2.provider.code.pkce;

import com.efa.security.oauth2.provider.code.AbstractExtendedAuthorizationCodeServices;
import com.efa.security.oauth2.provider.code.AuthorizationCodeGenerator;
import com.efa.security.oauth2.provider.code.AuthorizationCodeStore;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;

import static org.springframework.security.oauth2.core.endpoint.PkceParameterNames.CODE_VERIFIER;

/**
 * PKCE-aware implementation of extended authorization code services that emphasizes that only a code verifier is additionally checked.
 */
public abstract class PkceAwareExtendedAuthorizationCodeServices
        extends AbstractExtendedAuthorizationCodeServices<PkceAwareAuthorizationCodeStoreItem<OAuth2Authentication>> {
    
    public PkceAwareExtendedAuthorizationCodeServices(
            AuthorizationCodeGenerator authorizationCodeGenerator,
            AuthorizationCodeStore<OAuth2Authentication, PkceAwareAuthorizationCodeStoreItem<OAuth2Authentication>> authorizationCodeStore) {
        super(authorizationCodeGenerator, authorizationCodeStore);
    }
    
    protected void verify(PkceAwareAuthorizationCodeStoreItem<OAuth2Authentication> storeItem, TokenRequest tokenRequest) {
        if (!storeItem.isPkceFlow()) {
            return;
        }
        final String codeVerifier = tokenRequest.getRequestParameters().get(CODE_VERIFIER);
        if (codeVerifier == null) {
            throw new InvalidRequestException("A code verifier must be supplied.");
        }
        verify((PkceAuthorizationCodeStoreItem<OAuth2Authentication>) storeItem, codeVerifier);
    }
    
    protected abstract void verify(PkceAuthorizationCodeStoreItem<OAuth2Authentication> storeItem, String codeVerifier);
    
}
