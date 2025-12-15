package com.skillshub.gateway_service.user.client.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
public class UserServiceCreateUserRequest {
    private final String externalId;
    private final String firstName;
    private final String lastName;
    private final String email;
    private final String address;
    private final String city;
    private final String country;
    private final String phoneNumber;
    private final String postalCode;
    private final Set<String> roles;

    private UserServiceCreateUserRequest(
            String externalId,
            String firstName,
            String lastName,
            String email,
            String address,
            String city,
            String country,
            String phoneNumber,
            String postalCode,
            Set<String> roles
    ) {
        this.externalId = externalId;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.address = address;
        this.city = city;
        this.country = country;
        this.phoneNumber = phoneNumber;
        this.postalCode = postalCode;
        this.roles = normalizeRoles(roles);

        validate();
    }

    public static UserServiceCreateUserRequest of(
            String externalId,
            String firstName,
            String lastName,
            String email,
            String address,
            String city,
            String country,
            String phoneNumber,
            String postalCode,
            Set<String> roles
    ) {
        return new UserServiceCreateUserRequest(
                externalId,
                firstName,
                lastName,
                email,
                address,
                city,
                country,
                phoneNumber,
                postalCode,
                roles
        );
    }


    private void validate() {
        if (externalId == null || externalId.isBlank()) {
            throw new IllegalArgumentException("externalId is required");
        } else {
            // ok
        }

        if (firstName == null || firstName.isBlank()) {
            throw new IllegalArgumentException("firstName is required");
        } else {
            // ok
        }

        if (lastName == null || lastName.isBlank()) {
            throw new IllegalArgumentException("lastName is required");
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

        if (roles.stream().anyMatch(r -> r == null || r.isBlank())) {
            throw new IllegalArgumentException("roles contains blank value");
        } else {
            // ok
        }
    }

    private Set<String> normalizeRoles(Set<String> roles) {
        if (roles == null) {
            return Set.of();
        } else {
            return roles.stream()
                    .filter(r -> r != null && !r.isBlank())
                    .map(r -> r.trim().toUpperCase())
                    .collect(Collectors.toSet());
        }
    }
}
