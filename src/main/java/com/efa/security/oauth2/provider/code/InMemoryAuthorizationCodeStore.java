package com.efa.security.oauth2.provider.code;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of an authorization code store that stores the codes and items in memory.
 */
public class InMemoryAuthorizationCodeStore<I, U extends AuthorizationCodeStoreItem<I>> implements AuthorizationCodeStore<I, U> {
    
    protected final ConcurrentHashMap<String, U> authorizationCodeStore = new ConcurrentHashMap<>();
    
    @Override
    public void store(String authorizationCode, U storeItem) {
        authorizationCodeStore.put(authorizationCode, storeItem);
    }
    
    @Override
    public U get(String authorizationCode) {
        return authorizationCodeStore.remove(authorizationCode);
    }
    
}
