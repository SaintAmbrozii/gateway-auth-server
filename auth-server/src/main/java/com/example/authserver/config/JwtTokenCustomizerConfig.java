package com.example.authserver.config;


import com.example.authserver.domain.User;

import com.example.authserver.service.CustomUserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames.ID_TOKEN;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;


@Configuration(proxyBeanMethods = false)
public class JwtTokenCustomizerConfig {


    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(
            CustomUserDetailService userInfoService) {

        return context -> {
            if (ID_TOKEN.equals(context.getTokenType().getValue())
                    || ACCESS_TOKEN.equals(context.getTokenType())) {
                User userInfo =
                         userInfoService.loadUserByUsername(context.getPrincipal().getName());
                Map<String, Object> info = new HashMap<>();
                info.put("roles", userInfo.getAuthorities());
                info.put("user_id",userInfo.getId());
                context.getClaims().claims(claims -> claims.putAll(info));
                context.getJwsHeader().type("jwt");
            }
        };
    }


}
