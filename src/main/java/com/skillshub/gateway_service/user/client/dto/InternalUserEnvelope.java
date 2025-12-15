package com.skillshub.gateway_service.user.client.dto;

public record InternalUserEnvelope(
        boolean created,
        InternalUserResponse user
) {
}
