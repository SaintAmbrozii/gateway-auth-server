package com.example.authserver.domain;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@RequiredArgsConstructor
public enum Roles implements GrantedAuthority {

    ROLE_ADMIN,ROLE_USER;

    @Override
    public String getAuthority() {
        return name();
    }
}
