package com.skillshub.gateway_service.auth.filter;

import com.skillshub.gateway_service.auth.service.CookieService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * This filter runs AFTER authentication has been resolved by AuthCookieWebFilter.
 * Its job is to propagate user identity to backend microservices via HTTP headers:
 * <p>
 * - X-User-Id
 * - X-User-Email
 * - X-User-Roles
 * <p>
 * Backends are IAM-agnostic → they only trust Gateway metadata.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class XUserHeadersFilter implements WebFilter {

    private final CookieService cookieService;

    private static final PathPattern AUTH_PATH =
            PathPatternParser.defaultInstance.parse("/api/auth/**");

    private static final PathPattern OAUTH_PATH =
            PathPatternParser.defaultInstance.parse("/login/oauth2/**");

    private static final PathPattern OAUTH2_PATH =
            PathPatternParser.defaultInstance.parse("/oauth2/**");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        PathContainer path = exchange.getRequest().getPath().pathWithinApplication();

        // NEVER inject headers into auth or OAuth2 paths
        if (AUTH_PATH.matches(path)
                || OAUTH_PATH.matches(path)
                || OAUTH2_PATH.matches(path)) {
            return chain.filter(exchange);
        }

        return cookieService.extractUserFromCookie(exchange)
                .flatMap(claims -> {

                    String userId = (String) claims.getOrDefault("sub", "");
                    String email = (String) claims.getOrDefault("email", "");
                    List<String> roles = extractRoles(claims);

                    ServerHttpRequest mutated = exchange.getRequest().mutate()
                            .header("X-User-Id", userId)
                            .header("X-User-Email", email)
                            .header("X-User-Roles", String.join(",", roles))
                            .build();

                    return chain.filter(exchange.mutate().request(mutated).build());
                })
                .switchIfEmpty(chain.filter(exchange)); // no cookie = anonymous request
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Map<String, Object> claims) {
        try {
            Map<String, Object> realmAccess =
                    (Map<String, Object>) claims.get("realm_access");

            if (realmAccess == null) return List.of();

            return (List<String>) realmAccess.getOrDefault("roles", List.of());
        } catch (Exception e) {
            log.warn("⚠️ Failed to extract roles", e);
            return List.of();
        }
    }
}