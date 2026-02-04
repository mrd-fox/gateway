package com.skillshub.gateway_service.auth.filter;

import com.skillshub.gateway_service.auth.service.CookieService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * This filter runs AFTER authentication has been resolved by AuthCookieWebFilter.
 * Its job is to propagate user identity to backend microservices via HTTP headers:
 *
 * - X-User-Id
 * - X-User-Email
 * - X-User-Roles
 *
 * Backends are IAM-agnostic → they only trust Gateway metadata.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE + 50)
public class XUserHeadersFilter implements GlobalFilter {

    private static final String HEADER_USER_ID = "X-User-Id";
    private static final String HEADER_USER_EMAIL = "X-User-Email";
    private static final String HEADER_USER_ROLES = "X-User-Roles";

    private static final List<String> ALLOWED_ROLES = List.of("STUDENT", "TUTOR", "ADMIN");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (shouldBypass(path)) {
            return chain.filter(exchange);
        }

        String existingUserId = exchange.getRequest().getHeaders().getFirst(HEADER_USER_ID);
        if (!isBlank(existingUserId)) {
            return chain.filter(exchange);
        }

        log.info("🔥 XUserHeadersFilter HIT path={}", path);

        return ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> securityContext.getAuthentication())
                .flatMap(authentication -> {
                    Map<String, Object> claims = extractClaims(authentication);

                    if (claims == null) {
                        log.debug("No claims in SecurityContext -> 401. path={}", path);
                        return unauthorized(exchange);
                    }

                    String userId = asString(claims.get("sub"));
                    String email = asString(claims.get("email"));
                    List<String> roles = extractRoles(authentication, claims);

                    if (isBlank(userId)) {
                        log.debug("Missing sub claim -> 401. path={}", path);
                        return unauthorized(exchange);
                    }

                    log.info("✅ claims sub={}", userId);

                    ServerHttpRequest mutated = exchange.getRequest().mutate()
                            .headers(h -> {
                                h.set(HEADER_USER_ID, userId);
                                h.set(HEADER_USER_EMAIL, email != null ? email : "");
                                h.set(HEADER_USER_ROLES, String.join(",", roles));
                            })
                            .build();

                    return chain.filter(exchange.mutate().request(mutated).build());
                })
                .switchIfEmpty(Mono.defer(() -> {
                    // No SecurityContext -> not authenticated -> never forward to backend.
                    log.debug("No SecurityContext -> 401. path={}", path);
                    return unauthorized(exchange);
                }));
    }

    private boolean shouldBypass(String path) {
        if (!path.startsWith("/api/")) {
            return true;
        }

        if (path.startsWith("/api/auth/")
                || path.startsWith("/login/oauth2/")
                || path.startsWith("/oauth2/")) {
            return true;
        }

        if (path.startsWith("/api/users/")) {
            return true;
        }

        return false;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> extractClaims(Authentication authentication) {
        if (authentication == null) {
            return null;
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }

        return null;
    }

    private List<String> extractRoles(Authentication authentication, Map<String, Object> claims) {

        // Prefer authorities if present
        if (authentication != null && authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
            List<String> filtered = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .map(String::trim)
                    .filter(r -> !r.isBlank())
                    .map(String::toUpperCase)
                    .filter(ALLOWED_ROLES::contains)
                    .distinct()
                    .toList();

            if (!filtered.isEmpty()) {
                return filtered;
            }
        }

        // Fallback to realm_access.roles if authorities are empty
        try {
            Object realmAccessObj = claims.get("realm_access");
            if (!(realmAccessObj instanceof Map<?, ?> realmAccess)) {
                return List.of("STUDENT");
            }

            Object rolesObj = ((Map<?, ?>) realmAccess).get("roles");
            if (!(rolesObj instanceof List<?> rolesList)) {
                return List.of("STUDENT");
            }

            List<String> filtered = rolesList.stream()
                    .map(String::valueOf)
                    .map(String::trim)
                    .filter(r -> !r.isBlank())
                    .map(String::toUpperCase)
                    .filter(ALLOWED_ROLES::contains)
                    .distinct()
                    .toList();

            if (filtered.isEmpty()) {
                return List.of("STUDENT");
            }

            return filtered;
        } catch (Exception e) {
            log.warn("Failed to extract roles from claims", e);
            return List.of("STUDENT");
        }
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}