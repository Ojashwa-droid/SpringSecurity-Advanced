package com.ojashwa.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    /**
     * Converts a JWT token received from Keycloak into a collection of GrantedAuthorities, which are used by Spring Security to determine
     * the roles and permissions of a user.
     *
     * @param source the JWT token received from Keycloak
     * @return a collection of GrantedAuthorities representing the roles and permissions of the user
     */
    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        List<String> roles = (ArrayList<String>) source.getClaims().get("roles");
        if (roles == null || roles.isEmpty()) {
            return new ArrayList<>();
        }

        Collection<GrantedAuthority> returnValue = roles.stream()
                .map(roleName -> "ROLE_" + roleName)
                .map(role -> new SimpleGrantedAuthority(role))
                .collect(Collectors.toList());

        return returnValue;
    }
}