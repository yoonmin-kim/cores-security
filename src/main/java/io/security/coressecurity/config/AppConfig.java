package io.security.coressecurity.config;

import io.security.coressecurity.repository.AccessIpRepository;
import io.security.coressecurity.repository.ResourcesRepository;
import io.security.coressecurity.service.SecurityResourceService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class AppConfig {

    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository, AccessIpRepository accessIpRepository) {
        return new SecurityResourceService(resourcesRepository, accessIpRepository);
    }
}
