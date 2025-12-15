package com.skillshub.gateway_service.user.client.dto;

import java.util.Set;

public record InternalUserResponse(
        String id,
        String externalId,
        String firstName,
        String lastName,
        String email,
        String address,
        String city,
        String country,
        String phoneNumber,
        String postalCode,
        boolean active,
        Set<RoleResponse> roles
) {

}
