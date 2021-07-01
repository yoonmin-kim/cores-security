package io.security.coressecurity.controller.admin;

import io.security.coressecurity.domain.dto.ResourcesDTO;
import io.security.coressecurity.domain.entity.Resources;
import io.security.coressecurity.domain.entity.Role;
import io.security.coressecurity.repository.RoleRepository;
import io.security.coressecurity.security.metadatasource.UrlFilterInvocationSecurityMetadatsSource;
import io.security.coressecurity.service.MethodSecurityService;
import io.security.coressecurity.service.ResourcesService;
import io.security.coressecurity.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@RequiredArgsConstructor
@Controller
public class ResourcesController {

    private final ResourcesService resourcesService;
    private final RoleRepository roleRepository;
    private final RoleService roleService;
    private final MethodSecurityService methodSecurityService;
    private final UrlFilterInvocationSecurityMetadatsSource filterInvocationSecurityMetadatsSource;

    @GetMapping(value="/admin/resources")
    public String getResources(Model model) throws Exception {

        List<Resources> resources = resourcesService.getResources();
        model.addAttribute("resources", resources);

        return "admin/resource/list";
    }

    @PostMapping(value="/admin/resources")
    public String createResources(ResourcesDTO resourcesDto) throws Exception {

        ModelMapper modelMapper = new ModelMapper();
        Role role = roleRepository.findByRoleName(resourcesDto.getRoleName());
        Set<Role> roles = new HashSet<>();
        roles.add(role);
        Resources resources = modelMapper.map(resourcesDto, Resources.class);
        resources.setRoleSet(roles);

        resourcesService.createResources(resources);
        if("url".equals(resourcesDto.getResourceType())) {
            filterInvocationSecurityMetadatsSource.reload();
        }else{
            methodSecurityService.addMethodSecured(resourcesDto.getResourceName(), resourcesDto.getRoleName());
        }

        return "redirect:/admin/resources";
    }

    @GetMapping(value="/admin/resources/register")
    public String viewRoles(Model model) throws Exception {

        List<Role> roleList = roleService.getRoles();
        model.addAttribute("roleList", roleList);

        ResourcesDTO resources = new ResourcesDTO();
        Set<Role> roleSet = new HashSet<>();
        roleSet.add(new Role());
        resources.setRoleSet(roleSet);
        model.addAttribute("resources", resources);

        return "admin/resource/detail";
    }

    @GetMapping(value="/admin/resources/{id}")
    public String getResources(@PathVariable String id, Model model) throws Exception {

        List<Role> roleList = roleService.getRoles();
        model.addAttribute("roleList", roleList);
        Resources resources = resourcesService.getResources(Long.valueOf(id));

        ModelMapper modelMapper = new ModelMapper();
        ResourcesDTO resourcesDto = modelMapper.map(resources, ResourcesDTO.class);
        model.addAttribute("resources", resourcesDto);

        return "admin/resource/detail";
    }

    @GetMapping(value="/admin/resources/delete/{id}")
    public String removeResources(@PathVariable String id, Model model) throws Exception {

        Resources resources = resourcesService.getResources(Long.valueOf(id));
        resourcesService.deleteResources(Long.valueOf(id));
        if("url".equals(resources.getResourceType())) {
            filterInvocationSecurityMetadatsSource.reload();
        }else{
            methodSecurityService.removeMethodSecured(resources.getResourceName());
        }
        return "redirect:/admin/resources";
    }
}