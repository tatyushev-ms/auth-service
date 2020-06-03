package com.efa.security.oauth2.provider.code.pkce;

import com.efa.security.oauth2.provider.code.AuthorizationCodeStoreItem;
import lombok.AllArgsConstructor;

/**
 * Straightforward implementation of {@link AuthorizationCodeStoreItem}, simply
 * holding the value as given at construction and returning it from {@link #get()}.
 */
@AllArgsConstructor
public class SimpleAuthorizationCodeStoreItem<I> implements AuthorizationCodeStoreItem<I> {
    
    private final I item;
    
    @Override
    public I get() {
        return item;
    }
    
}
