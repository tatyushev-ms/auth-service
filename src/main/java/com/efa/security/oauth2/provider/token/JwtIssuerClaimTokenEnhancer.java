package com.efa.security.oauth2.provider.token;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.util.Assert;

import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;

public class JwtIssuerClaimTokenEnhancer implements TokenEnhancer {
    
    /**
     * Default field name for the Issuer claim.
     */
    private static final String ISS = JwtClaimNames.ISS;
    
    private final URL issuer;
    
    public JwtIssuerClaimTokenEnhancer(URL issuer) {
        this(ISS, issuer);
    }
    
    public JwtIssuerClaimTokenEnhancer(String fieldName, URL issuer) {
        Assert.notNull(fieldName, "field name cannot be null");
        Assert.notNull(issuer, "issuer cannot be null");
        this.issuer = issuer;
    }
    
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        final DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
        final Map<String, Object> info = new LinkedHashMap<>(accessToken.getAdditionalInformation());
        if (!info.containsKey(ISS)) {
            info.put(ISS, issuer);
        }
        result.setAdditionalInformation(info);
        return result;
    }
    
}
