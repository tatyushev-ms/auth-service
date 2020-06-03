package com.efa.client;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;
import java.util.Set;

public class DemoClientDetailsService implements ClientDetailsService {
    
    private final boolean autoApprove = true;
    
    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        final BaseClientDetails result = new BaseClientDetails();
        result.setClientId("first-client");
        result.setAuthorizedGrantTypes(Collections.singletonList("authorization_code"));
        //result.setAccessTokenValiditySeconds(accessTokenValiditySeconds);
        //result.setRefreshTokenValiditySeconds(refreshTokenValiditySeconds);
        result.setRegisteredRedirectUri(Collections.singleton("http://localhost:8081/oauth/login/client-app"));
        result.setClientSecret(null);
        final Set<String> scopes = Collections.singleton("profile");
        result.setScope(scopes);
        //result.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
        //result.setResourceIds(resourceIds);
        //result.setAdditionalInformation(additionalInformation);
        if (autoApprove) {
            result.setAutoApproveScopes(scopes);
        } else {
            result.setAutoApproveScopes(Collections.emptySet());
        }
        return result;
    }
    
}
