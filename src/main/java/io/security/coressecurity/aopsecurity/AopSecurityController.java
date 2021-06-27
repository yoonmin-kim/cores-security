package io.security.coressecurity.aopsecurity;

import io.security.coressecurity.domain.dto.AccountDTO;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class AopSecurityController {

    @GetMapping("preAuthorize")
    @PreAuthorize("hasRole('ROLE_USER') and #account.username == principal.username")
    public String preAuthorize(AccountDTO account, Model model, Principal principal) {
        model.addAttribute("method", "Success @PreAuthorize");
        return "/aop/method";
    }
}
