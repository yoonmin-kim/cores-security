package io.security.coressecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.coressecurity.domain.dto.AccountDTO;
import io.security.coressecurity.security.token.AjaxAuthenticationToken;
import io.security.coressecurity.util.WebUtil;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.util.StringUtils.*;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if (!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported");
        }

        AccountDTO accountDTO = objectMapper.readValue(request.getReader(), AccountDTO.class);
        if (!hasText(accountDTO.getUsername()) || !hasText(accountDTO.getPassword())) {
            throw new AuthenticationServiceException("Username or Password is empty");
        }

        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDTO.getUsername(), accountDTO.getPassword());

        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }
}
