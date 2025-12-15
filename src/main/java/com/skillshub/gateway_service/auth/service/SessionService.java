package com.skillshub.gateway_service.auth.service;

import com.skillshub.gateway_service.auth.AuthCookieProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * SessionService centralizes all authentication flow logic:
 * <p>
 * - start login (redirect to Keycloak)
 * - handle Keycloak callback (exchange code → token, set cookie, redirect)
 * - logout (clear cookie, redirect)
 * <p>
 * Controller becomes a thin layer delegating to this service.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SessionService {

    private final CookieService cookieService;
    private final AuthCookieProperties props;


    /**
     * START LOGIN (Frontend calls /api/auth/login)
     * Delegates to Spring Security OAuth2 login mechanism.
     */
    public Mono<Void> performLogin(ServerWebExchange exchange) {
        log.info("➡️  Starting OAuth2 login: redirecting to Keycloak...");
        ServerHttpResponse response = exchange.getResponse();

        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create("/oauth2/authorization/keycloak"));

        return response.setComplete();
    }

    /**
     * LOGIN SUCCESS HANDLER (Spring Security already did the OAuth2 flow)
     * We only create the cookie + redirect to frontend.
     */
    public Mono<Void> handleLoginSuccess(String jwt, ServerWebExchange exchange) {

        if (jwt == null) {
            log.error("❌ No JWT provided to handleLoginSuccess()");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        log.info("🔐 OAuth2 login OK → Creating session cookie…");

        ResponseCookie cookie = cookieService.createAuthCookie(jwt);

        if (cookie == null) {
            log.error("❌ Failed to create authentication cookie.");
            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return exchange.getResponse().setComplete();
        }

        ServerHttpResponse response = exchange.getResponse();
        response.addCookie(cookie);

        log.info("➡️  Redirecting user to frontend: {}", props.getRedirectAfterLogin());

        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(props.getRedirectAfterLogin()));

        return response.setComplete();
    }

    /**
     * LOGOUT → Clear cookie → Redirect to frontend
     */
    public Mono<Void> performLogout(ServerWebExchange exchange) {
        log.info("🔓 Logout requested → Clearing cookie…");

        ServerHttpResponse response = exchange.getResponse();

        ResponseCookie clearCookie = cookieService.clearAuthCookie();
        response.addCookie(clearCookie);

        log.info("➡️  Redirecting user after logout: {}", props.getRedirectAfterLogout());

        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(props.getRedirectAfterLogout()));

        return response.setComplete();
    }
}