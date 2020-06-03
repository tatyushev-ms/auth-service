package com.efa.security.oauth2.provider.code.pkce;

import java.util.HashMap;
import java.util.Map;

/**
 * Selects which implementation of {@link CodeVerifierTransformer} should
 * be used based on the value of {@link CodeChallengeMethod}.
 */
public class DefaultCodeVerifierTransformerSelector implements CodeVerifierTransformerSelector {
    
    private final Map<CodeChallengeMethod, CodeVerifierTransformer> map = new HashMap<>();
    
    public DefaultCodeVerifierTransformerSelector() {
        map.put(CodeChallengeMethod.PLAIN, new PlainCodeVerifierTransformer());
        map.put(CodeChallengeMethod.S256, new SecureCodeVerifierTransformer());
    }
    
    @Override
    public CodeVerifierTransformer select(CodeChallengeMethod codeChallengeMethod) {
        return map.get(codeChallengeMethod);
    }
    
}
