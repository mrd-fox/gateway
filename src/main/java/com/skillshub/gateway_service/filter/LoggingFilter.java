package com.skillshub.gateway_service.filter;

import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPInputStream;

@Slf4j
@Component
public class LoggingFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        HttpHeaders headers = request.getHeaders();

        log.info("➡️  Incoming request: {} {}", request.getMethod(), request.getURI());
        log.debug("🔑 Authorization: {}", headers.getFirst("Authorization"));
        log.debug("👤 X-User-Email: {}", headers.getFirst("X-User-Email"));
        log.debug("🧩 X-User-Roles: {}", headers.getFirst("X-User-Roles"));

        ServerHttpResponse originalResponse = exchange.getResponse();

        // Decorate the response
        ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                if (body instanceof Flux) {
                    Flux<? extends DataBuffer> fluxBody = (Flux<? extends DataBuffer>) body;
                    return super.writeWith(
                            fluxBody.flatMap(dataBuffer -> {
                                byte[] content = new byte[dataBuffer.readableByteCount()];
                                dataBuffer.read(content);
                                DataBufferUtils.release(dataBuffer);

                                String bodyStr = decodeBody(content, getHeaders().getFirst(HttpHeaders.CONTENT_ENCODING));

                                if (bodyStr.trim().startsWith("{") || bodyStr.trim().startsWith("[")) {
                                    log.info("📦 Response JSON Body: {}", bodyStr);
                                } else {
                                    log.info("📦 Response Body (non-JSON): {}", bodyStr);
                                }

                                DataBuffer buffer = originalResponse.bufferFactory().wrap(content);
                                return Flux.just(buffer);
                            })
                    );
                }
                return super.writeWith(body);
            }
        };

        return chain.filter(exchange.mutate().response(decoratedResponse).build())
                .doOnSuccess(v -> {
                    int statusCode = exchange.getResponse().getStatusCode() != null
                            ? exchange.getResponse().getStatusCode().value()
                            : 0;
                    log.info("⬅️  Response status for {} {} -> {}", request.getMethod(), request.getURI(), statusCode);
                });
    }

    @Override
    public int getOrder() {
        return 10;
    }


    private String decodeBody(byte[] content, String encoding) {
        if ("gzip".equalsIgnoreCase(encoding)) {
            try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(content))) {
                return new String(gzip.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                log.warn("⚠️ Failed to decompress gzip body: {}", e.getMessage());
                return "[unreadable gzip content]";
            }
        }
        return new String(content, StandardCharsets.UTF_8);
    }
}