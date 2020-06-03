package com.efa.account;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Profile("demo")
@Service
public class DemoUserDetailsService implements UserDetailsService {
    
    private final PasswordEncoder passwordEncoder;
    
    public DemoUserDetailsService(@Qualifier("userDetailsServicePasswordEncoder") PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final boolean active = true;
        
        final List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList("bombom1,bombom2,bombom3");
        
        return new CustomUser("spaceman", passwordEncoder.encode("kurlik"), "12345",
                active, active, active, active,
                grantedAuthorities);
    }
    
}
