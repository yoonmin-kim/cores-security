package io.security.coressecurity.service.impl;

import io.security.coressecurity.domain.entity.Role;
import io.security.coressecurity.repository.RoleRepository;
import io.security.coressecurity.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@RequiredArgsConstructor
@Service
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;

    @Transactional
    public Role getRole(long id) {
        return roleRepository.findById(id).orElse(new Role());
    }

    @Transactional
    public List<Role> getRoles() {

        return roleRepository.findAll();
    }

    @Transactional
    public void createRole(Role role){

        roleRepository.save(role);
    }

    @Transactional
    public void deleteRole(long id) {
        roleRepository.deleteById(id);
    }
}