package com.skillshub.gateway_service.auth.filter;

import com.skillshub.gateway_service.auth.service.CookieService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
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

    private final CookieService cookieService;

    private static final List<String> ALLOWED_ROLES = List.of("STUDENT", "TUTOR", "ADMIN");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // NEVER inject headers into auth or OAuth2 paths
        if (path.startsWith("/api/auth/")
                || path.startsWith("/login/oauth2/")
                || path.startsWith("/oauth2/")) {
            return chain.filter(exchange);
        }

        // Avoid loops / unnecessary work for gateway-local user endpoints
        if (path.startsWith("/api/users/")) {
            return chain.filter(exchange);
        }

        // Only enrich API calls
        if (!path.startsWith("/api/")) {
            return chain.filter(exchange);
        }
        log.info("🔥 XUserHeadersFilter HIT path={}", exchange.getRequest().getURI().getPath());

        return cookieService.extractUserFromCookie(exchange)
                .doOnNext(claims -> log.info("✅ claims sub={}", claims.get("sub")))
                .flatMap(claims -> {
                    String userId = asString(claims.get("sub"));
                    String email = asString(claims.get("email"));
                    List<String> roles = extractRoles(claims);

                    if (isBlank(userId)) {
                        return chain.filter(exchange);
                    }

                    ServerHttpRequest mutated = exchange.getRequest().mutate()
                            .headers(h -> {
                                h.set("X-User-Id", userId);
                                h.set("X-User-Email", email != null ? email : "");
                                h.set("X-User-Roles", String.join(",", roles));
                            })
                            .build();

                    return chain.filter(exchange.mutate().request(mutated).build());
                })
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("❌ No claims -> no headers injected");
                    return chain.filter(exchange);
                }));
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private String asString(Object value) {
        if (value == null) {
            return null;
        } else {
            return String.valueOf(value);
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Map<String, Object> claims) {
        try {
            Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
            if (realmAccess == null) {
                return List.of("STUDENT");
            }

            List<String> roles = (List<String>) realmAccess.getOrDefault("roles", List.of());

            List<String> filtered = roles.stream()
                    .map(String::valueOf)
                    .map(String::trim)
                    .filter(r -> !r.isBlank())
                    .map(String::toUpperCase)
                    .filter(ALLOWED_ROLES::contains)
                    .distinct()
                    .toList();

            if (filtered.isEmpty()) {
                return List.of("STUDENT");
            } else {
                return filtered;
            }
        } catch (Exception e) {
            log.warn("⚠️ Failed to extract roles", e);
            return List.of("STUDENT");
        }
    }
}