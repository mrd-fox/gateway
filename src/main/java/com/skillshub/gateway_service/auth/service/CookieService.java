package com.skillshub.gateway_service.auth.service;

import com.skillshub.gateway_service.auth.AuthCookieProperties;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CookieService {

    private final AuthCookieProperties props;
    private final JwtDecoderService jwtDecoderService;

    @PostConstruct
    public void debugConfig() {
        log.error("COOKIE DEBUG → secure={}, sameSite={}", props.isCookieSecure(), props.getCookieSameSite());
    }

    public ResponseCookie createAuthCookie(String accessToken) {
        ResponseCookie.ResponseCookieBuilder builder =
                ResponseCookie.from(props.getCookieName(), accessToken)
                        .httpOnly(true)
                        // Must match the deployment (HTTP vs HTTPS)
                        .secure(props.isCookieSecure())
                        .path("/")
                        .sameSite(props.getCookieSameSite())
                        .maxAge(props.getCookieMaxAge());

        // IMPORTANT: In local/docker we usually do not set a domain.
        if (props.getCookieDomain() != null && !props.getCookieDomain().isBlank()) {
            builder.domain(props.getCookieDomain());
        }

        return builder.build();
    }

    public ResponseCookie clearAuthCookie() {
        ResponseCookie.ResponseCookieBuilder builder =
                ResponseCookie.from(props.getCookieName(), "")
                        .httpOnly(true)
                        // MUST match createAuthCookie(), otherwise the browser won't delete the cookie.
                        .secure(props.isCookieSecure())
                        .path("/")
                        .sameSite(props.getCookieSameSite())
                        .maxAge(0);

        if (props.getCookieDomain() != null && !props.getCookieDomain().isBlank()) {
            builder.domain(props.getCookieDomain());
        }

        return builder.build();
    }

    public Mono<Map<String, Object>> extractUserFromCookie(ServerWebExchange exchange) {
        var cookie = exchange.getRequest().getCookies().getFirst(props.getCookieName());

        if (cookie == null) {
            log.warn("No auth cookie found");
            return Mono.empty();
        }

        try {
            return Mono.just(jwtDecoderService.decodeJwt(cookie.getValue()));
        } catch (Exception e) {
            log.warn("Invalid JWT: {}", e.getMessage());
            return Mono.empty();
        }
    }
}
