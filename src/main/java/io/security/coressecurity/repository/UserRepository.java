package io.security.coressecurity.repository;

import io.security.coressecurity.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<Account, Long> {
    Account findByUsername(String username);

    @Query("select count(a) from Account a where a.username = :username ")
    int countByUsername(String username);
}
