package com.efa.account;

import com.efa.authority.Authority;
import org.apache.commons.lang.math.RandomUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
@DisplayName("SimpleUserDetailsService tests")
class SimpleUserDetailsServiceTest {
    
    @InjectMocks
    private SimpleUserDetailsService simpleUserDetailsService;
    
    @Mock
    private AccountRepository accountRepository;
    
    @Test
    @DisplayName("Loads a user by a username")
    void shouldLoadByUsernameWhenUserExists() {
        //given
        final String username = "demo";
        final Account account = new Account(
                123L, username, "adfasd", true, new HashSet<>(createAuthorityList("ROLE_ADMIN", "ROLE_USER")));
        given(accountRepository.findByUsername(username)).willReturn(Optional.of(account));
        
        //when
        UserDetails loaded = simpleUserDetailsService.loadUserByUsername(username);
        
        //then
        assertThat(loaded.getUsername(), is(equalTo("demo")));
        assertThat(loaded.getPassword(), is(equalTo("adfasd")));
        assertThat(loaded.isEnabled(), is(true));
        assertThat(loaded.isAccountNonExpired(), is(true));
        assertThat(loaded.isCredentialsNonExpired(), is(true));
        assertThat(loaded.isAccountNonLocked(), is(true));
        final var authorities = loaded.getAuthorities();
        assertThat(authorities, hasSize(2));
        assertThat(authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()), containsInAnyOrder("ROLE_ADMIN", "ROLE_USER"));
    }
    
    @Test
    @DisplayName("Throws UsernameNotFoundException when the user could not be found")
    void shouldFailToLoadByUsernameWhenUserNotExists() {
        final Exception exception = assertThrows(UsernameNotFoundException.class, () ->
                simpleUserDetailsService.loadUserByUsername("demo"));
        assertThat(exception.getMessage(), is(equalTo("username demo not found!")));
    }
    
    @Test
    @DisplayName("Throws UsernameNotFoundException when the user has no authority")
    void shouldFailToLoadByUsernameWhenUserHasNoAuthority() {
        //given
        final String username = "demo";
        final Account account = new Account(123L, username, "adfasd", true, new HashSet<>());
        given(accountRepository.findByUsername(username)).willReturn(Optional.of(account));
        
        //then
        final Exception exception = assertThrows(UsernameNotFoundException.class, () ->
                simpleUserDetailsService.loadUserByUsername(username));
        assertThat(exception.getMessage(), is(equalTo("user with username demo has no authority!")));
    }
    
    private static Set<Authority> createAuthorityList(String... authorities) {
        final Set<Authority> result = new HashSet<>(authorities.length);
        
        for (final String authority : authorities) {
            result.add(new Authority(RandomUtils.nextLong(), authority));
        }
        
        return result;
    }
    
}
