package com.efa;

import com.efa.account.CustomUser;
import lombok.extern.apachecommons.CommonsLog;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Public claims can be defined at will by those using JWTs. However, in order to prevent collisions, they should be
 * defined in the IANA JSON Web Token Registry or be defined as a URI that contains a collision resistant namespace.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7519#section-4.2">JSON Web Token (JWT) Public Claim Names</a>
 * @see <a href="https://www.iana.org/assignments/jwt/jwt.xhtml">IANA JSON Web Token Registry</a>
 */
@CommonsLog
public class JwtAccountNumberClaimTokenEnhancer implements TokenEnhancer {
    
    private static final String CLAIM_NAME = "account_number";
    
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        final DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
        final Map<String, Object> info = new LinkedHashMap<>(accessToken.getAdditionalInformation());
        final Object principal = authentication.getUserAuthentication().getPrincipal();
        if (!(principal instanceof CustomUser)) {
            log.warn("Authentication doesn't store CustomUser instance");
            return result;
        }
        if (info.containsKey(CLAIM_NAME)) {
            log.warn("Already contains such fields");
            return result;
        }
        final CustomUser customUser = (CustomUser) principal;
        info.put(CLAIM_NAME, customUser.getAccountNumber());
        result.setAdditionalInformation(info);
        return result;
    }
    
}
