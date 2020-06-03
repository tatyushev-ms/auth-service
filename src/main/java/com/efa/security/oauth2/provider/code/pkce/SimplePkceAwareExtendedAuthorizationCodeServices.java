package com.efa.security.oauth2.provider.code.pkce;

import com.efa.security.oauth2.provider.code.AuthorizationCodeGenerator;
import com.efa.security.oauth2.provider.code.AuthorizationCodeStore;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Map;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.endpoint.PkceParameterNames.CODE_CHALLENGE;

/**
 * Implementation of extended authorization code services that handle PKCE.
 * https://tools.ietf.org/html/rfc7636
 */
public class SimplePkceAwareExtendedAuthorizationCodeServices extends PkceAwareExtendedAuthorizationCodeServices {
    
    private final CodeVerifierTransformerSelector codeVerifierTransformerSelector = new DefaultCodeVerifierTransformerSelector();
    private final ClientDetailsService clientDetailsService;
    
    public SimplePkceAwareExtendedAuthorizationCodeServices(
            AuthorizationCodeGenerator authorizationCodeGenerator,
            AuthorizationCodeStore<OAuth2Authentication, PkceAwareAuthorizationCodeStoreItem<OAuth2Authentication>> authorizationCodeStore,
            ClientDetailsService clientDetailsService) {
        super(authorizationCodeGenerator, authorizationCodeStore);
        this.clientDetailsService = clientDetailsService;
    }
    
    @Override
    protected PkceAwareAuthorizationCodeStoreItem<OAuth2Authentication> makeStoreItem(OAuth2Authentication authentication) {
        final Map<String, String> requestParameters = authentication.getOAuth2Request().getRequestParameters();
        final String clientId = requestParameters.get(CLIENT_ID);
        final boolean containsCodeChallenge = requestParameters.containsKey(CODE_CHALLENGE);
        
        if (isPublicClient(clientId) && !containsCodeChallenge) {
            throw new InvalidRequestException("A code challenge must be supplied.");
        }
        
        if (!containsCodeChallenge) {
            return new NonPkceAuthorizationCodeStoreItem<>(authentication);
        }
        
        final String codeChallenge = requestParameters.get(CODE_CHALLENGE);
        final CodeChallengeMethod codeChallengeMethod = getCodeChallengeMethod(requestParameters);
        return new PkceAuthorizationCodeStoreItem<>(authentication, codeChallenge, codeChallengeMethod);
    }
    
    @Override
    protected void verify(PkceAuthorizationCodeStoreItem<OAuth2Authentication> storeItem, String codeVerifier) {
        final CodeVerifierTransformer codeVerifierTransformer = codeVerifierTransformerSelector.select(storeItem.getCodeChallengeMethod());
        if (codeVerifierTransformer == null) {
            throw new IllegalStateException("CodeVerifierTransformer does not support such CodeChallengeMethod");
        }
        final String calculatedCodeChallenge = codeVerifierTransformer.transform(codeVerifier);
        if (!storeItem.getCodeChallenge().equals(calculatedCodeChallenge)) {
            throw new InvalidGrantException("Invalid code verifier.");
        }
    }
    
    private boolean isPublicClient(String clientId) {
        final ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
        return !clientDetails.isSecretRequired();
    }
    
    private CodeChallengeMethod getCodeChallengeMethod(Map<String, String> requestParameters) {
        final String codeChallengeMethod = requestParameters.get("code_challenge_method");
        if (codeChallengeMethod == null) {
            return CodeChallengeMethod.PLAIN;
        }
        try {
            return CodeChallengeMethod.valueOf(codeChallengeMethod.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("Illegal code challenge method");
        }
    }
    
}
