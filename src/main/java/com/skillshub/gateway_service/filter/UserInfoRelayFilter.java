package com.skillshub.gateway_service.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

// Global filter that extracts user information from JWT and forwards it as headers
@Component
public class UserInfoRelayFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        return ReactiveSecurityContextHolder.getContext()
                .flatMap(securityContext -> {
                    Authentication authentication = securityContext.getAuthentication();

                    if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {

                        String userId = jwt.getClaimAsString("sub");
                        String email = jwt.getClaimAsString("email");
                        List<String> roles = jwt.getClaimAsStringList("roles");

                        // If Keycloak uses realm_access instead of "roles"
                        if (roles == null && jwt.hasClaim("realm_access")) {
                            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
                            Object rolesObj = realmAccess.get("roles");

                            if (rolesObj instanceof List<?> roleList) {
                                roles = roleList.stream()
                                        .map(Object::toString)
                                        .toList();
                            }
                        }

                        // Mutate request and add custom headers
                        ServerHttpRequest mutatedRequest = exchange.getRequest()
                                .mutate()
                                .header("X-User-Id", userId != null ? userId : "unknown")
                                .header("X-User-Email", email != null ? email : "unknown")
                                .header("X-User-Roles", roles != null ? String.join(",", roles) : "none")
                                .build();

                        return chain.filter(exchange.mutate().request(mutatedRequest).build());
                    }

                    return chain.filter(exchange);
                })
                .switchIfEmpty(chain.filter(exchange)); // if no context, continue without modification
    }

    @Override
    public int getOrder() {
        // Runs early so headers are present before routing
        return -1;
    }
}
