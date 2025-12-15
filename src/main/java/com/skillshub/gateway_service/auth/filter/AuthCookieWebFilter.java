package com.skillshub.gateway_service.auth.filter;

import com.skillshub.gateway_service.auth.service.JwtDecoderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Extracts the SKILLSHUB_AUTH cookie, decodes JWT,
 * and injects authentication into the reactive SecurityContext.
 * <p>
 * Mandatory for:
 * - /api/auth/me
 * - X-User-* propagation to backend
 * - role checks in Gateway routes
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthCookieWebFilter implements WebFilter {

    private final JwtDecoderService jwtDecoderService;

    private static final String COOKIE_NAME = "SKILLSHUB_AUTH";
    private static final PathPattern AUTH_PATH =
            PathPatternParser.defaultInstance.parse("/api/auth/**");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        PathContainer path = exchange.getRequest().getPath().pathWithinApplication();
        if (AUTH_PATH.matches(path)) {
            return chain.filter(exchange); // 👈 PAS DE COOKIE CHECK
        }

        ServerHttpRequest request = exchange.getRequest();

        HttpCookie cookie = request.getCookies().getFirst(COOKIE_NAME);
        if (cookie == null || cookie.getValue().isBlank()) {
            return chain.filter(exchange);
        }

        Map<String, Object> claims;
        try {
            claims = jwtDecoderService.decodeJwt(cookie.getValue());
        } catch (Exception e) {
            log.error("❌ Invalid JWT cookie", e);
            return chain.filter(exchange);
        }

        List<String> roles = extractRoles(claims);

        AbstractAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        claims,
                        null,
                        roles.stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toSet())
                );

        return Mono.deferContextual(context ->
                chain.filter(exchange)
        ).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Map<String, Object> claims) {
        try {
            Map<String, Object> realmAccess =
                    (Map<String, Object>) claims.get("realm_access");

            if (realmAccess == null) return List.of();

            return (List<String>) realmAccess.getOrDefault("roles", List.of());
        } catch (Exception e) {
            log.warn("⚠️ Failed to extract roles from JWT", e);
            return List.of();
        }
    }
}