package com.efa.security.oauth2.provider.code.pkce;

/**
 * Calculates "code_challenge" from the received "code_verifier".
 * https://tools.ietf.org/html/rfc7636#section-4.6
 */
public interface CodeVerifierTransformer {
    
    String transform(String codeVerifier);
    
}
