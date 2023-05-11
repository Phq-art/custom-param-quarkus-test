package org.wayne;

import io.quarkus.security.Authenticated;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.SecurityContext;
import org.eclipse.microprofile.jwt.JsonWebToken;
import jakarta.inject.Inject;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.core.MediaType;
import org.wayne.customresolver.KeycloakRole;
import org.wayne.customresolver.KeycloakRoleContext;
import java.security.Principal;
import java.util.Collection;
import java.util.Set;

import static io.quarkus.arc.ComponentsProvider.LOG;

@Path("/api/profile")
@Authenticated
@ApplicationScoped
public class AdminResource {

    @Inject
    JsonWebToken jwt;

    @GET
    @Path("/custom-role-ep")
    @Produces(MediaType.APPLICATION_JSON)
    public void getRoles(@Context KeycloakRoleContext keycloakRoleContext) {
        LOG.info("adsjlksajdl");
        Set<String> roles = keycloakRoleContext.getRoles();
    }

    @GET
    @Path("/custom-role-ep-param")
    @Consumes(MediaType.APPLICATION_JSON)
    public Collection<String> customEp(@KeycloakRole(realm = "profiler", role = "view-all") Set<String> userRoles) {
        LOG.info("JWT: " + jwt);
        LOG.info("User roles: " + userRoles);
        return userRoles;
    }

    @GET
    @RolesAllowed("view-all")
    @Produces(MediaType.TEXT_PLAIN)
    public String admin(@Context SecurityContext securityContext) {
        return "Access for user " + jwt.getName() + " with subject " + jwt.getSubject() + " is granted";
    }

    @GET
    @Path("roles-allowed")
    @RolesAllowed("view-all")
    @Produces(MediaType.TEXT_PLAIN)
    public String helloRolesAllowed(@Context SecurityContext securityContext) {
        Principal caller = securityContext.getUserPrincipal();
        return getResponseString(securityContext) + ", birthdate: " + jwt.getClaim("birthdate").toString();
    }

    private String getResponseString(SecurityContext securityContext) {
        String name;
        if (securityContext.getUserPrincipal() == null) {
            name = "anonymous";
        } else if (!securityContext.getUserPrincipal().getName().equals(jwt.getName())) {
            throw new InternalServerErrorException("Principal and JsonWebToken names do not match");
        } else {
            name = securityContext.getUserPrincipal().getName();
        }
        return String.format("hello %s,"
                        + " isHttps: %s,"
                        + " authScheme: %s",
                name, securityContext.isSecure(), securityContext.getAuthenticationScheme());
    }
}