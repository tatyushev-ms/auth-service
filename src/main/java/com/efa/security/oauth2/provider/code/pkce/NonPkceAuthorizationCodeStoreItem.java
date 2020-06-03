package com.efa.security.oauth2.provider.code.pkce;

/**
 * PKCE aware {@link com.efa.security.oauth2.provider.code.AuthorizationCodeStoreItem} implementation for non PKCE flow.
 */
public class NonPkceAuthorizationCodeStoreItem<I> extends SimpleAuthorizationCodeStoreItem<I> implements PkceAwareAuthorizationCodeStoreItem<I> {
    
    public NonPkceAuthorizationCodeStoreItem(I item) {
        super(item);
    }
    
    @Override
    public boolean isPkceFlow() {
        return false;
    }
    
}
