package com.efa.security.oauth2.provider.code.pkce;

import com.efa.security.oauth2.provider.code.AuthorizationCodeStoreItem;

/**
 * A basic PKCE aware {@link AuthorizationCodeStoreItem} interface allowing checking
 * whether it stores data created during the PKCE flow.
 */
public interface PkceAwareAuthorizationCodeStoreItem<I> extends AuthorizationCodeStoreItem<I> {
    
    boolean isPkceFlow();
    
}
