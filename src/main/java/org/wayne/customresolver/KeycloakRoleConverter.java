package org.wayne.customresolver;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.ext.ParamConverter;

import java.util.Set;

public class KeycloakRoleConverter implements ParamConverter<Set<String>> {
    private final Set<String> userRoles;

    public KeycloakRoleConverter(Set<String> userRoles) {
        this.userRoles = userRoles;
    }

    @Override
    public Set<String> fromString(String value) {
        if (!userRoles.contains(value)) {
            throw new WebApplicationException("User does not have required role");
        }
        return Set.of(value);
    }

    @Override
    public String toString(Set<String> value) {
        return value.iterator().next();
    }
}