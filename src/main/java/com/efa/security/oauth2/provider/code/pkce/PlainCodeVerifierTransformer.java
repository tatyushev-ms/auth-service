package com.efa.security.oauth2.provider.code.pkce;

/**
 * Calculates "code_challenge" from the received "code_verifier", if "code_challenge_method" is "plain".
 */
public class PlainCodeVerifierTransformer implements CodeVerifierTransformer {
    
    @Override
    public String transform(String codeVerifier) {
        return codeVerifier;
    }
    
}
