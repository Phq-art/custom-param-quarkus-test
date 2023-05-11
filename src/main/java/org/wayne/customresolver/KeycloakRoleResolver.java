package org.wayne.customresolver;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.RequestScoped;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.ext.ParamConverter;
import jakarta.ws.rs.ext.ParamConverterProvider;
import jakarta.ws.rs.ext.Provider;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;

import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static io.quarkus.arc.ComponentsProvider.LOG;

@RequestScoped
//@ApplicationScoped
@Provider
//@Priority(Priorities.USER)
public class KeycloakRoleResolver implements ParamConverterProvider {
    @Context
    SecurityContext securityContext;

    @SuppressWarnings("unchecked")
    @Override
    public <T> ParamConverter<T> getConverter(Class<T> rawType, Type genericType, Annotation[] annotations) {
        LOG.infof("getConverter has been called");
        for (Annotation annotation : annotations) {
            if (annotation.annotationType() == KeycloakRole.class) {
                KeycloakRole keycloakRole = (KeycloakRole) annotation;
                Set<String> userRoles = getUserRoles(keycloakRole.realm());
                return (ParamConverter<T>) new KeycloakRoleConverter(userRoles);
            }
        }
        return null;
    }

    private Set<String> getUserRoles(String realm) {
        LOG.infof("getUserRoles has been called");
        KeycloakSecurityContext keycloakSecurityContext = (KeycloakSecurityContext) securityContext;
        AccessToken token = keycloakSecurityContext.getToken();
        if (token == null) {
            throw new WebApplicationException("Unable to obtain user roles");
        }

        Map<String, Object> otherClaims = token.getOtherClaims();
        JsonArray resourceAccessArray = (JsonArray) otherClaims.get("resource_access");
        JsonObject resourceAccess = resourceAccessArray.getJsonObject(0);
        JsonObject profilerCore = resourceAccess.getJsonObject("profiler-core");
        JsonArray rolesArray = profilerCore.getJsonArray("roles");

        Set<String> userRoles = new HashSet<>();
        for (int i = 0; i < rolesArray.size(); i++) {
            userRoles.add(rolesArray.getString(i));
        }

        return userRoles;
    }

//    private Set<String> getUserRoles(String realm) {
//        KeycloakSecurityContext keycloakSecurityContext = (KeycloakSecurityContext) securityContext;
//        AccessToken token = keycloakSecurityContext.getToken();
//        if (token == null) {
//            throw new WebApplicationException("Unable to obtain user roles");
//        }
//        return token.getRealmAccess().getRoles();
//    }

    public boolean isUserInRole(String role) {
        KeycloakSecurityContext keycloakSecurityContext = (KeycloakSecurityContext) securityContext.getUserPrincipal();
        if (keycloakSecurityContext == null) {
            return false;
        }
        KeycloakPrincipal<?> principal = (KeycloakPrincipal<?>) securityContext.getUserPrincipal();
        if (principal == null) {
            return false;
        }

        return principal.getKeycloakSecurityContext().getToken().getRealmAccess().getRoles().contains(role);
    }

//    static class KeycloakRoleConverter implements ParamConverter<Set<String>> {
//        private final Set<String> userRoles;
//        public KeycloakRoleConverter(Set<String> userRoles) {
//            this.userRoles = userRoles;
//        }
//
//        @Override
//        public Set<String> fromString(String value) {
//            if (!userRoles.contains(value)) {
//                throw new WebApplicationException("User does not have required role");
//            }
//            return Set.of(value);
//        }
//
//        @Override
//        public String toString(Set<String> value) {
//            return value.iterator().next();
//        }
//    }
}
