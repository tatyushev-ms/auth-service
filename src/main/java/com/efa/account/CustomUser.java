package com.efa.account;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.*;

/**
 * Similar to a {@link org.springframework.security.core.userdetails.User}, and holds an {@link #accountNumber}
 */
public class CustomUser implements UserDetails, CredentialsContainer {
    
    private static final long serialVersionUID = -944751352428102131L;
    
    private final String username;
    private String password;
    private final String accountNumber;
    private final Set<GrantedAuthority> authorities;
    private final boolean accountNonExpired;
    private final boolean accountNonLocked;
    private final boolean credentialsNonExpired;
    private final boolean enabled;
    
    public CustomUser(String username, String password, String accountNumber, Collection<? extends GrantedAuthority> authorities) {
        this(username, password, accountNumber, true, true, true, true, authorities);
    }
    
    public CustomUser(String username, String password, String accountNumber, boolean enabled, boolean accountNonExpired,
                      boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        if (((username == null) || "".equals(username)) || (password == null)) {
            throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
        }
        
        this.username = username;
        this.password = password;
        this.accountNumber = accountNumber;
        this.enabled = enabled;
        this.accountNonExpired = accountNonExpired;
        this.credentialsNonExpired = credentialsNonExpired;
        this.accountNonLocked = accountNonLocked;
        this.authorities = Collections.unmodifiableSet(sortAuthorities(authorities));
    }
    
    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return authorities;
    }
    
    @Override
    public String getPassword() {
        return password;
    }
    
    @Override
    public String getUsername() {
        return username;
    }
    
    public String getAccountNumber() {
        return accountNumber;
    }
    
    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }
    
    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }
    
    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }
    
    @Override
    public boolean isEnabled() {
        return enabled;
    }
    
    @Override
    public void eraseCredentials() {
        password = null;
    }
    
    private static SortedSet<GrantedAuthority> sortAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Assert.notNull(authorities, "Cannot pass a null GrantedAuthority collection");
        // Ensure array iteration order is predictable; as per UserDetails.getAuthorities() contract
        final SortedSet<GrantedAuthority> sortedAuthorities = new TreeSet<>(new AuthorityComparator());
        
        for (final GrantedAuthority grantedAuthority : authorities) {
            Assert.notNull(grantedAuthority, "GrantedAuthority list cannot contain any null elements");
            sortedAuthorities.add(grantedAuthority);
        }
        
        return sortedAuthorities;
    }
    
    private static class AuthorityComparator implements Comparator<GrantedAuthority>, Serializable {
        
        private static final long serialVersionUID = -7435284251230363937L;
        
        public int compare(GrantedAuthority g1, GrantedAuthority g2) {
            // Neither should ever be null as each entry is checked before adding it to the set.
            // If the authority is null, it is a custom authority and should precede others.
            if (g2.getAuthority() == null) {
                return -1;
            }
            if (g1.getAuthority() == null) {
                return 1;
            }
            return g1.getAuthority().compareTo(g2.getAuthority());
        }
        
    }
    
    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final CustomUser that = (CustomUser) o;
        return username.equals(that.username);
    }
    
    @Override
    public int hashCode() {
        return username.hashCode();
    }
    
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append(super.toString()).append(": ");
        sb.append("Username: ").append(username).append("; ");
        sb.append("Password: [PROTECTED]; ");
        sb.append("AccountNumber: ").append(accountNumber).append("; ");
        sb.append("Enabled: ").append(enabled).append("; ");
        sb.append("AccountNonExpired: ").append(accountNonExpired).append("; ");
        sb.append("credentialsNonExpired: ").append(credentialsNonExpired).append("; ");
        sb.append("AccountNonLocked: ").append(accountNonLocked).append("; ");
        
        if (!authorities.isEmpty()) {
            sb.append("Granted Authorities: ");
            
            boolean first = true;
            for (final GrantedAuthority auth : authorities) {
                if (!first) {
                    sb.append(",");
                }
                first = false;
                
                sb.append(auth);
            }
        } else {
            sb.append("Not granted any authorities");
        }
        
        return sb.toString();
    }
    
}
