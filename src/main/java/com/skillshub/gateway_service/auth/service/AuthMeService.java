package com.skillshub.gateway_service.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * AuthMeService:
 * Returns authenticated user info extracted from the JWT
 * (already validated by JwtDecoderService and stored in SecurityContext).
 * Used by /api/auth/me route.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthMeService {

    public Mono<Map<String, Object>> me(ServerWebExchange exchange) {

        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication())
                .flatMap(this::extractUserFromAuthentication)
                .switchIfEmpty(unauthorized());
    }

    private Mono<Map<String, Object>> extractUserFromAuthentication(Authentication authentication) {

        if (authentication == null || !authentication.isAuthenticated()) {
            return unauthorized();
        }

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof Map)) {
            return unauthorized();
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) principal;

        if (claims.isEmpty()) {
            return unauthorized();
        }

        String id = (String) claims.get("sub");
        String email = (String) claims.get("email");

        if (id == null || email == null) {
            return unauthorized();
        }

        return Mono.just(Map.of(
                "id", id,
                "email", email,
                "roles", extractRoles(claims)
        ));
    }

    private Mono<Map<String, Object>> unauthorized() {
        return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized"));
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Map<String, Object> claims) {
        try {
            Map<String, Object> realmAccess =
                    (Map<String, Object>) claims.get("realm_access");

            if (realmAccess == null) {
                return List.of();
            }

            return (List<String>) realmAccess.getOrDefault("roles", List.of());
        } catch (Exception e) {
            log.warn("⚠️ Failed to extract roles from JWT", e);
            return List.of();
        }
    }
}