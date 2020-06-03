package com.efa.security.oauth2.provider.code.pkce;

/**
 * An {@link com.efa.security.oauth2.provider.code.AuthorizationCodeStoreItem} implementation
 * for PKCE flow which additionally stores "code_challenge" and "code_challenge_method" values.
 */
public class PkceAuthorizationCodeStoreItem<I> extends SimpleAuthorizationCodeStoreItem<I> implements PkceAwareAuthorizationCodeStoreItem<I> {
    
    private final String codeChallenge;
    private final CodeChallengeMethod codeChallengeMethod;
    
    public PkceAuthorizationCodeStoreItem(I item, String codeChallenge, CodeChallengeMethod codeChallengeMethod) {
        super(item);
        this.codeChallengeMethod = codeChallengeMethod;
        this.codeChallenge = codeChallenge;
    }
    
    @Override
    public boolean isPkceFlow() {
        return true;
    }
    
    public CodeChallengeMethod getCodeChallengeMethod() {
        return codeChallengeMethod;
    }
    
    public String getCodeChallenge() {
        return codeChallenge;
    }
    
}
