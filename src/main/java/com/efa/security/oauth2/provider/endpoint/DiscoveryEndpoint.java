package com.efa.security.oauth2.provider.endpoint;

import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@FrameworkEndpoint
@AllArgsConstructor
public class DiscoveryEndpoint {
    
    /**
     * issuer                                - The fully qualified issuer URL of the server
     * authorization_endpoint                - The fully qualified URL of the server’s authorization endpoint defined by RFC 6749
     * jwks_uri                              - The fully qualified URI of the server’s public key in JSON Web Key Set (JWKS) format
     * response_types_supported              (OpenID Connect Discovery)
     * subject_types_supported               (OpenID Connect Discovery)
     * id_token_signing_alg_values_supported (OpenID Connect Discovery)
     * token_endpoint                        - The fully qualified URL of the server’s token endpoint defined by RFC 6749
     * introspection_endpoint                - The fully qualified URL of the server’s introspection_endpoint defined by OAuth 2.0 Token Introspection
     * revocation_endpoint                   - The fully qualified URL of the server’s revocation endpoint defined by OAuth 2.0 Authorization Server Metadata (and sort of in OAuth 2.0 Token Revocation)
     */
    @GetMapping("/.well-known/openid-configuration")
    @ResponseBody
    public Map<String, Object> getKey(Principal principal) {
        final Map<String, Object> result = new HashMap<>();
        result.put("issuer", serverUrl().build().toUriString());
        result.put("authorization_endpoint", serverUrl().path("/oauth/authorize").toUriString());// TODO: Is it should be /authorize
        result.put("jwks_uri", serverUrl().path("/.well-known/jwks.json").toUriString());
        result.put("response_types_supported", Arrays.asList("code", "code id_token", "id_token", "token id_token"));
        result.put("subject_types_supported", Arrays.asList("public", "pairwise"));
        result.put("id_token_signing_alg_values_supported", Collections.singletonList("RS256"));
        result.put("token_endpoint", serverUrl().path("/oauth/token").toUriString());
        //result.put("introspection_endpoint", "");
        //result.put("revocation_endpoint", "");
        return result;
    }
    
    private ServletUriComponentsBuilder serverUrl() {
        return ServletUriComponentsBuilder.fromCurrentContextPath();
    }
    
}
