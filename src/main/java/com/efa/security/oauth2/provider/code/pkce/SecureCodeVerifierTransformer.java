package com.efa.security.oauth2.provider.code.pkce;

import lombok.SneakyThrows;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Calculates "code_challenge" from the received "code_verifier", if "code_challenge_method" is "S256".
 */
public class SecureCodeVerifierTransformer implements CodeVerifierTransformer {
    
    @Override
    public String transform(String codeVerifier) {
        final MessageDigest messageDigest = getMessageDigest();
        final byte[] digest = messageDigest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
    
    @SneakyThrows
    private MessageDigest getMessageDigest() {
        return MessageDigest.getInstance("SHA-256");
    }
    
}
