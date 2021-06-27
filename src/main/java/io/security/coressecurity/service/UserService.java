package io.security.coressecurity.service;

import io.security.coressecurity.domain.dto.AccountDTO;
import io.security.coressecurity.domain.entity.Account;

import java.util.List;

public interface UserService {

    void createUser(Account account);

    void modifyUser(AccountDTO accountDto);

    List<Account> getUsers();

    AccountDTO getUser(Long id);

    void deleteUser(Long idx);

    void order();
}
