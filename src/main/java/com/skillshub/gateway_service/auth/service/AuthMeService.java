package com.skillshub.gateway_service.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
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
 * <p>
 * Used by /api/auth/me route.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthMeService {

    private final CookieService cookieService;

    /**
     * Extract user identity from the JWT stored in the auth cookie.
     */
    //works
//    public Mono<Map<String, Object>> me(ServerWebExchange exchange) {
//
//        return cookieService.extractUserFromCookie(exchange)
//                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized")))
//                .map(claims -> Map.of(
//                        "id", claims.getOrDefault("sub", "unknown"),
//                        "email", claims.getOrDefault("email", "unknown"),
//                        "roles", extractRoles(claims)
//                ));
//    }
    public Mono<Map<String, Object>> me(ServerWebExchange exchange) {

        return cookieService.extractUserFromCookie(exchange)
                .flatMap(claims -> {

                    if (claims == null || claims.isEmpty()) {
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
                })
                .switchIfEmpty(unauthorized());
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