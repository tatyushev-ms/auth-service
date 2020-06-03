package com.efa.account;

import com.efa.authority.Authority;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
@Profile("!demo")
public class SimpleUserDetailsService implements UserDetailsService {
    
    private final AccountRepository accountRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final Optional<Account> optionalAccount = accountRepository.findByUsername(username);
        if (optionalAccount.isEmpty()) {
            throw new UsernameNotFoundException(String.format("username %s not found!", username));
        }
        final Account account = optionalAccount.get();
        final Set<Authority> authorities = account.getAuthorities();
        if (authorities.isEmpty()) {
            throw new UsernameNotFoundException(String.format("user with username %s has no authority!", username));
        }
        
        final boolean active = account.isActive();
        
        final List<GrantedAuthority> grantedAuthorities = authorities.stream()
                .map(Authority::getName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        
        return new CustomUser(account.getUsername(), account.getPassword(), "12345",
                active, active, active, active,
                grantedAuthorities);
    }
    
}
