package com.efa.security.oauth2.provider.code;

/**
 * Basic interface for a data store, which associates {@link AuthorizationCodeStoreItem}
 * with the authorization code so it can be verified later.
 */
public interface AuthorizationCodeStore<I, U extends AuthorizationCodeStoreItem<I>> {
    
    void store(String authorizationCode, U storeItem);
    
    U get(String authorizationCode);
    
}
