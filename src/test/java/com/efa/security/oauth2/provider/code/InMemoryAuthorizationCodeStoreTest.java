package com.efa.security.oauth2.provider.code;

import com.efa.security.oauth2.provider.code.pkce.SimpleAuthorizationCodeStoreItem;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@DisplayName("InMemoryAuthorizationCodeStore tests")
class InMemoryAuthorizationCodeStoreTest {
    
    private final InMemoryAuthorizationCodeStore<?, AuthorizationCodeStoreItem<Object>> store = new InMemoryAuthorizationCodeStore<>();
    
    @Test
    @DisplayName("Stores an item")
    void shouldStoreItem() {
        //given
        final String authorizationCode = "echidna";
        final AuthorizationCodeStoreItem<Object> expectedObject = new SimpleAuthorizationCodeStoreItem<>("any object");
        store.store(authorizationCode, expectedObject);
        
        //when
        final var actualObject = store.get(authorizationCode);
        
        //then
        assertThat(actualObject, is(equalTo(expectedObject)));
    }
    
    @Test
    @DisplayName("Removes an item when returns")
    void shouldRemoveItemWhenReturn() {
        //given
        final String authorizationCode = "echidna";
        final AuthorizationCodeStoreItem<Object> expectedObject = new SimpleAuthorizationCodeStoreItem<>("any object");
        store.store(authorizationCode, expectedObject);
        
        store.get(authorizationCode);
        
        //when
        final var actualObject = store.get(authorizationCode);
        
        //then
        assertThat(actualObject, is(nullValue()));
    }
    
}
