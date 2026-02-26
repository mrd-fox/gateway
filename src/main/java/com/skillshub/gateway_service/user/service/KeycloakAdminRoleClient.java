package com.skillshub.gateway_service.user.service;

import reactor.core.publisher.Mono;

public interface KeycloakAdminRoleClient {
    Mono<Void> addRealmRoleToUser(String userId, String roleName);

    Mono<Void> removeRealmRoleFromUser(String userId, String roleName);
}