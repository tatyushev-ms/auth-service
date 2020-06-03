package com.efa.security.oauth2.provider;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.io.Serializable;
import java.util.*;

/**
 * Factory for tests to create OAuth2Request objects.
 */
public class RequestTokenFactory {
    
    public static OAuth2Request createOAuth2Request(Map<String, String> requestParameters, String clientId,
                                                    Collection<? extends GrantedAuthority> authorities, boolean approved, Collection<String> scope,
                                                    Set<String> resourceIds, String redirectUri, Set<String> responseTypes,
                                                    Map<String, Serializable> extensionProperties) {
        return new OAuth2Request(requestParameters, clientId, authorities, approved, scope == null ? null
                : new LinkedHashSet<>(scope), resourceIds, redirectUri, responseTypes, extensionProperties);
    }
    
    public static OAuth2Request createOAuth2Request(String clientId, boolean approved) {
        return createOAuth2Request(Collections.emptyMap(), clientId, null, approved, null, null, null, null, null);
    }
    
    public static OAuth2Request createCorrectOAuth2Request(Map<String, String> parameters, ClientDetails clientDetails, boolean approved) {
        return createOAuth2Request(parameters, clientDetails.getClientId(), clientDetails.getAuthorities(), approved,
                clientDetails.getScope(), clientDetails.getResourceIds(),
                clientDetails.getRegisteredRedirectUri() == null ? null : clientDetails.getRegisteredRedirectUri().iterator().next(),
                null, null);
    }
    
}
