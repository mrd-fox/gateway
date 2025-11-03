package com.skillshub.gateway_service.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class LoggingFilter implements GlobalFilter, Ordered {

    private static final Logger logger = LoggerFactory.getLogger(LoggingFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        HttpHeaders headers = request.getHeaders();

        // Log request details
        logger.info("➡️  Incoming request: {} {}", request.getMethod(), request.getURI());
        logger.debug("🔑 Authorization: {}", headers.getFirst("Authorization"));
        logger.debug("👤 X-User-Email: {}", headers.getFirst("X-User-Email"));
        logger.debug("🧩 X-User-Roles: {}", headers.getFirst("X-User-Roles"));

        // Continue with chain and log after response
        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            int statusCode = exchange.getResponse().getStatusCode() != null
                    ? exchange.getResponse().getStatusCode().value()
                    : 0;
            logger.info("⬅️  Response status for {} {} -> {}",
                    request.getMethod(),
                    request.getURI(),
                    statusCode);
        }));
    }

    @Override
    public int getOrder() {
        // Run after security and user info filters
        return 10;
    }
}