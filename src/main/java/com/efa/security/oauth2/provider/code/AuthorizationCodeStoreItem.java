package com.efa.security.oauth2.provider.code;

/**
 * An (item) object representing a store item value.
 */
public interface AuthorizationCodeStoreItem<I> {
    
    /**
     * Return the actual value in the item.
     */
    I get();
    
}
