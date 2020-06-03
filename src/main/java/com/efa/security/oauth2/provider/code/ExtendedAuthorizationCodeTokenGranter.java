package com.efa.security.oauth2.provider.code;

import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REDIRECT_URI;

/**
 * Token granter for the authorization code grant type. The same as
 * {@link org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter},
 * but uses {@link ExtendedAuthorizationCodeServices} instead of
 * {@link org.springframework.security.oauth2.provider.code.AuthorizationCodeServices}.
 */
public class ExtendedAuthorizationCodeTokenGranter extends AbstractTokenGranter {
    
    private static final String GRANT_TYPE = AUTHORIZATION_CODE.getValue();
    
    private final ExtendedAuthorizationCodeServices extendedAuthorizationCodeServices;
    
    public ExtendedAuthorizationCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
                                                 ExtendedAuthorizationCodeServices extendedAuthorizationCodeServices,
                                                 ClientDetailsService clientDetailsService,
                                                 OAuth2RequestFactory requestFactory) {
        this(tokenServices, extendedAuthorizationCodeServices, clientDetailsService, requestFactory, GRANT_TYPE);
    }
    
    protected ExtendedAuthorizationCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
                                                    ExtendedAuthorizationCodeServices extendedAuthorizationCodeServices,
                                                    ClientDetailsService clientDetailsService,
                                                    OAuth2RequestFactory requestFactory,
                                                    String grantType) {
        super(tokenServices, clientDetailsService, requestFactory, grantType);
        this.extendedAuthorizationCodeServices = extendedAuthorizationCodeServices;
    }
    
    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        final OAuth2Authentication storedAuth = extendedAuthorizationCodeServices.consumeTokenRequest(tokenRequest);
        if (storedAuth == null) {
            throw new InternalAuthenticationServiceException(
                    "ExtendedAuthorizationCodeServices returned null, which is an interface contract violation");
        }
        
        final String redirectUri = tokenRequest.getRequestParameters().get(REDIRECT_URI);
        final OAuth2Request pendingOAuth2Request = storedAuth.getOAuth2Request();
        final String redirectUriApprovalParameter = pendingOAuth2Request.getRequestParameters().get(REDIRECT_URI);
        if ((redirectUri != null || redirectUriApprovalParameter != null) && !pendingOAuth2Request.getRedirectUri().equals(redirectUri)) {
            throw new RedirectMismatchException("Redirect URI mismatch.");
        }
        
        final String pendingClientId = pendingOAuth2Request.getClientId();
        final String clientId = tokenRequest.getClientId();
        if (clientId != null && !clientId.equals(pendingClientId)) {
            throw new InvalidClientException("Client ID mismatch");
        }
        
        final OAuth2Request finalStoredOAuth2Request = makeRequestWithTheCombinedParameters(pendingOAuth2Request, tokenRequest);
        
        final Authentication storedUserAuth = storedAuth.getUserAuthentication();
        
        return new OAuth2Authentication(finalStoredOAuth2Request, storedUserAuth);
        
    }
    
    /**
     * Make a new stored request with the combined parameters
     */
    private OAuth2Request makeRequestWithTheCombinedParameters(OAuth2Request pendingOAuth2Request, TokenRequest tokenRequest) {
        final Map<String, String> combinedParameters = combineParameters(pendingOAuth2Request, tokenRequest);
        
        return pendingOAuth2Request.createOAuth2Request(combinedParameters);
    }
    
    /**
     * Combine the parameters adding the new ones last so they override if there are any clashes
     */
    private Map<String, String> combineParameters(OAuth2Request pendingOAuth2Request, TokenRequest tokenRequest) {
        final Map<String, String> result = new HashMap<>(pendingOAuth2Request.getRequestParameters());
        result.putAll(tokenRequest.getRequestParameters());
        return result;
    }
    
}
