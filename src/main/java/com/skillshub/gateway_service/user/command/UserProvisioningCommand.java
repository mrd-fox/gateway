package com.skillshub.gateway_service.user.command;

import com.skillshub.gateway_service.user.client.dto.UserServiceCreateUserRequest;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

@Getter
@Setter
public class UserProvisioningCommand {
    private final UUID externalId;
    private final String email;
    private final String firstName;
    private final String lastName;
    private final List<String> roles;
    private static final List<String> ALLOWED_ROLES = List.of("STUDENT", "TUTOR", "ADMIN");

    private UserProvisioningCommand(UUID externalId, String email, String firstName, String lastName, List<String> roles) {
        this.externalId = externalId;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.roles = roles;
        validate();
    }

    /**
     * Build a command from raw Keycloak claim values.
     */
    public static UserProvisioningCommand fromClaims(String sub, String email, String firstName, String lastName, List<String> roles) {
        UUID externalId = parseExternalId(sub);
        List<String> safeRoles = normalizeRoles(roles);

        return new UserProvisioningCommand(externalId, email, firstName, lastName, safeRoles);
    }


    public List<String> getRoles() {
        return new ArrayList<>(roles);
    }

    /**
     * Map command to User-Service create payload.
     */
    public UserServiceCreateUserRequest mapToUserServiceCreateUserRequest() {
        return UserServiceCreateUserRequest.of(
                externalId.toString(),
                firstName,
                lastName,
                email,
                null,
                null,
                null,
                null,
                null,
                new HashSet<>(roles)
        );
    }

    private void validate() {
        if (externalId == null) {
            throw new IllegalArgumentException("externalId is required");
        } else {
            // ok
        }

        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email is required");
        } else {
            // ok
        }

        if (roles == null) {
            throw new IllegalArgumentException("roles is required");
        } else {
            // ok
        }
    }

    private static UUID parseExternalId(String sub) {
        if (sub == null || sub.isBlank()) {
            throw new IllegalArgumentException("sub (Keycloak subject) is required");
        } else {
            // ok
        }

        try {
            return UUID.fromString(sub);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("sub (Keycloak subject) must be a valid UUID", ex);
        }
    }

    private static List<String> normalizeRoles(List<String> roles) {

        List<String> normalized;

        if (roles == null) {
            normalized = List.of();
        } else {
            normalized = roles.stream()
                    .map(String::valueOf)
                    .map(String::trim)
                    .filter(r -> !r.isBlank())
                    .map(String::toUpperCase)
                    .filter(ALLOWED_ROLES::contains)
                    .distinct()
                    .toList();
        }

        if (normalized.isEmpty()) {
            return List.of("STUDENT");
        } else {
            return normalized;
        }
    }
}
