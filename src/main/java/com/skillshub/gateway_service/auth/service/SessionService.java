package com.skillshub.gateway_service.auth.service;

import com.skillshub.gateway_service.auth.AuthCookieProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Duration;

/**
 * SessionService centralizes all authentication flow logic:
 *
 * - start login (redirect to Keycloak)
 * - handle Keycloak callback (set cookies, redirect)
 * - logout (clear cookies, redirect)
 */
@Slf4j
@Service
public class SessionService {

    /**
     * Refresh cookie name is derived from the access cookie name to avoid adding config for now.
     * Example: SKILLSHUB_AUTH -> SKILLSHUB_AUTH_RT
     */
    private static final String REFRESH_COOKIE_SUFFIX = "_RT";

    /**
     * We set refresh cookie max-age to 7 days to support "remember me" sessions.
     * Even if the cookie remains longer, Keycloak will stop issuing refreshed tokens once SSO session expires.
     */
    private static final Duration REFRESH_COOKIE_MAX_AGE = Duration.ofDays(7);

    private final CookieService cookieService;
    private final AuthCookieProperties props;

    private final String keycloakBaseUrl;
    private final String realm;

    public SessionService(
            CookieService cookieService,
            AuthCookieProperties props,
            @Value("${app.keycloak.base-url}") String keycloakBaseUrl,
            @Value("${app.keycloak.realm}") String realm
    ) {
        this.cookieService = cookieService;
        this.props = props;
        this.keycloakBaseUrl = trimTrailingSlash(keycloakBaseUrl);
        this.realm = realm;
    }

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
     * We create the cookies (access + refresh) and redirect to frontend.
     */
    public Mono<Void> handleLoginSuccess(String accessToken, String refreshToken, ServerWebExchange exchange) {

        if (accessToken == null || accessToken.isBlank()) {
            log.error("❌ No access token provided to handleLoginSuccess()");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        log.info("🔐 OAuth2 login OK → Creating session cookies… refreshTokenPresent={}", refreshToken != null);

        // Access token cookie (existing behavior)
        ResponseCookie accessCookie = cookieService.createAuthCookie(accessToken);

        if (accessCookie == null) {
            log.error("❌ Failed to create access token cookie.");
            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return exchange.getResponse().setComplete();
        }

        ServerHttpResponse response = exchange.getResponse();
        response.addCookie(accessCookie);

        // Refresh token cookie (new behavior)
        if (refreshToken != null && !refreshToken.isBlank()) {
            ResponseCookie refreshCookie = createRefreshTokenCookie(refreshToken);
            response.addCookie(refreshCookie);
        } else {
            // Without refresh token, the user will be forced to re-login when access token expires.
            log.warn("⚠️ No refresh token received from Keycloak. Session will not be refreshable.");
        }

        log.info("➡️  Redirecting user to frontend: {}", props.getRedirectAfterLogin());

        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(props.getRedirectAfterLogin()));

        return response.setComplete();
    }

    public Mono<Void> performLogout(ServerWebExchange exchange) {
        log.info("🔓 Logout requested → Clearing cookies…");

        ServerHttpResponse response = exchange.getResponse();

        ResponseCookie clearAccessCookie = cookieService.clearAuthCookie();
        response.addCookie(clearAccessCookie);

        ResponseCookie clearRefreshCookie = clearRefreshTokenCookie();
        response.addCookie(clearRefreshCookie);

        log.info("➡️  Redirecting user after logout: {}", props.getRedirectAfterLogout());

        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(props.getRedirectAfterLogout()));

        return response.setComplete();
    }
    private ResponseCookie createRefreshTokenCookie(String refreshToken) {

        String refreshCookieName = props.getCookieName() + REFRESH_COOKIE_SUFFIX;

        ResponseCookie.ResponseCookieBuilder builder =
                ResponseCookie.from(refreshCookieName, refreshToken)
                        .httpOnly(true)
                        .secure(props.isCookieSecure())
                        .path("/")
                        .sameSite(props.getCookieSameSite())
                        .maxAge(REFRESH_COOKIE_MAX_AGE);

        // IMPORTANT: In local/docker we do not set domain
        if (props.getCookieDomain() != null && !props.getCookieDomain().isBlank()) {
            builder.domain(props.getCookieDomain());
        }

        return builder.build();
    }

    private ResponseCookie clearRefreshTokenCookie() {

        String refreshCookieName = props.getCookieName() + REFRESH_COOKIE_SUFFIX;

        ResponseCookie.ResponseCookieBuilder builder =
                ResponseCookie.from(refreshCookieName, "")
                        .httpOnly(true)
                        .secure(props.isCookieSecure())
                        .path("/")
                        .sameSite(props.getCookieSameSite())
                        .maxAge(0);

        if (props.getCookieDomain() != null && !props.getCookieDomain().isBlank()) {
            builder.domain(props.getCookieDomain());
        }

        return builder.build();
    }

    private String trimTrailingSlash(String s) {
        if (s == null) {
            return "";
        }
        if (s.endsWith("/")) {
            return s.substring(0, s.length() - 1);
        }
        return s;
    }
}