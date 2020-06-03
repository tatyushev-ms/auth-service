package com.efa.authority;

import com.efa.account.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthorityRepository extends JpaRepository<Account, Long> {
    
    Optional<Account> findByUsername(String username);
    
}
