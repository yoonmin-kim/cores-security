package io.security.coressecurity.service;

import io.security.coressecurity.domain.entity.Resources;
import io.security.coressecurity.repository.AccessIpRepository;
import io.security.coressecurity.repository.ResourcesRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class SecurityResourceService {

    private final ResourcesRepository resourcesRepository;
    private final AccessIpRepository accessIpRepository;

    @Transactional
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = resourcesRepository.findAllResources();
        resourcesList.forEach(resource -> {
            List<ConfigAttribute> configAttributesList = new ArrayList<>();
            resource.getRoleSet().forEach(role -> {
                configAttributesList.add(new SecurityConfig(role.getRoleName()));
            });
            result.put(new AntPathRequestMatcher(resource.getResourceName()), configAttributesList);
        });
        return result;
    }

    @Transactional
    public LinkedHashMap<String, List<ConfigAttribute>> getResourceList(String resourceType) {
        LinkedHashMap<String, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = findAllResources(resourceType);
        resourcesList.forEach(resource -> {
            List<ConfigAttribute> configAttributesList = new ArrayList<>();
            resource.getRoleSet().forEach(role -> {
                configAttributesList.add(new SecurityConfig(role.getRoleName()));
            });
            result.put(resource.getResourceName(), configAttributesList);
        });
        return result;
    }

    private List<Resources> findAllResources(String resourceType) {
        if("method".equals(resourceType))
            return resourcesRepository.findAllMethodResources();

        return resourcesRepository.findAllPointcutResources();
    }

    public List<String> getAccessIpList() {
        return accessIpRepository.findAll().stream().map(accessIp -> accessIp.getIpAddress()).collect(Collectors.toList());
    }

}
