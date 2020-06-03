package com.efa.security.oauth2.provider.code.pkce;

/**
 * Interface to be implemented by types that determine which {@link CodeVerifierTransformer}
 * instance should be used based on a given {@link CodeChallengeMethod}.
 */
public interface CodeVerifierTransformerSelector {
    
    CodeVerifierTransformer select(CodeChallengeMethod codeChallengeMethod);
    
}
