package com.efa.account;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@SpringJUnitConfig
@DataJpaTest
@DisplayName("AccountRepository tests")
class AccountRepositoryTest {
    
    @Autowired
    private AccountRepository accountRepository;
    
    @Test
    @DisplayName("Saves a user")
    public void savesUser() {
        //given
        final Account account = new Account();
        account.setUsername("name");
        account.setPassword("password");
        
        //when
        accountRepository.save(account);
        
        //then
        assertThat(account.getId(), is(notNullValue()));
    }
    
    @Disabled
    @Test
    @DisplayName("A lastModified field is set")
    public void lastModifiedFieldIsSet() {
    }
    
    @Disabled
    @Test
    @DisplayName("A createdAt field is set")
    public void createdAtFieldIsSet() {
    }
    
    @Disabled
    @Test
    @DisplayName("lastModified equals to createdAt after the first save")
    public void lastModifiedEqualsToCreatedAtAfterFirstSave() {
    }
    
    @Disabled
    @Test
    @DisplayName("lastModified differs from createdAt after the update")
    public void lastModifiedDiffersFromCreatedAtAfterUpdate() {
    }
    
    @Test
    @DisplayName("Finds a user")
    public void findsUser() {
        //given
        final Account account = new Account();
        account.setUsername("name");
        account.setPassword("password");
        
        //when
        accountRepository.save(account);
        
        final Optional<Account> found = accountRepository.findByUsername(account.getUsername());
        
        //then
        assertThat(found.isPresent(), is(true));
        assertThat(found.get().getUsername(), is(equalTo(account.getUsername())));
        assertThat(found.get().getPassword(), is(equalTo(account.getPassword())));
    }
    
}
