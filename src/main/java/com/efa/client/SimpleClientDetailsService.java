package com.efa.client;

import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

@AllArgsConstructor
public class SimpleClientDetailsService implements ClientDetailsService {
    
    private final ClientRepository clientRepository;
    
    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        return clientRepository.findByClientId(clientId)
                .map(this::toClientDetails)
                .orElseThrow(() -> new ClientRegistrationException(String.format("no client %s registered", clientId)));
    }
    
    private ClientDetails toClientDetails(final Client client) {
        final BaseClientDetails details = new BaseClientDetails(
                client.getClientId(), null, client.getScopes(), client.getAuthorizedGrantTypes(), client.getAuthorities());
        details.setClientSecret(client.getSecret());
        
        /*
        auto approved scopes
        details.setAutoApproveScopes(Arrays.asList(client.getAutoApproveScopes().split(",")));
        */
        
        /*
        redirect url
        String greetingsClientRedirectUri = Optional
                .ofNullable(loadBalancerClient.choose("greetings-client"))
                .map(si -> "http://" + si.getHost() + ':' + si.getPort() + '/')
                .orElseThrow(() -> new ClientRegistrationException("couldn't find and bind a greetings-client IP"));
        details.setRegisteredRedirectUri(Collections.singleton(greetingsClientRedirectUri));
        */
        
        return details;
    }
    
}
