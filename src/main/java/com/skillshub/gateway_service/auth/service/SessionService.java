package com.skillshub.gateway_service.auth.service;

import com.skillshub.gateway_service.auth.AuthCookieProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
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
 * - logout:
 *   - BACKCHANNEL logout to Keycloak (no UI) using refresh_token
 *   - clear cookies
 *   - redirect frontend
 */
@Slf4j
@Service
public class SessionService {

    private static final String REFRESH_COOKIE_SUFFIX = "_RT";

    private static final Duration REFRESH_COOKIE_MAX_AGE = Duration.ofDays(7);

    private final CookieService cookieService;
    private final AuthCookieProperties props;

    private final String keycloakBaseUrl;
    private final String realm;

    private final String gatewayClientId;

    private final WebClient webClient;

    public SessionService(
            CookieService cookieService,
            AuthCookieProperties props,
            WebClient.Builder webClientBuilder,
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            @Value("${app.keycloak.base-url}") String keycloakBaseUrl,
            @Value("${app.keycloak.realm}") String realm
    ) {
        this.cookieService = cookieService;
        this.props = props;
        this.keycloakBaseUrl = trimTrailingSlash(keycloakBaseUrl);
        this.realm = realm;
        this.webClient = webClientBuilder.build();

        // English comment: retrieve the OAuth client-id from Spring registration (keycloak)
        // This keeps config single-sourced (application.yml -> spring.security.oauth2.client.registration.keycloak.client-id)
        this.gatewayClientId = clientRegistrationRepository
                .findByRegistrationId("keycloak")
                .map(reg -> reg.getClientId())
                .blockOptional()
                .orElse("gateway-service");
    }

    public Mono<Void> performLogin(ServerWebExchange exchange) {
        log.info("➡️  Starting OAuth2 login: redirecting to Keycloak...");
        ServerHttpResponse response = exchange.getResponse();

        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create("/oauth2/authorization/keycloak"));

        return response.setComplete();
    }

    public Mono<Void> handleLoginSuccess(String accessToken, String refreshToken, ServerWebExchange exchange) {

        if (accessToken == null || accessToken.isBlank()) {
            log.error("❌ No access token provided to handleLoginSuccess()");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        log.info("🔐 OAuth2 login OK → Creating session cookies… refreshTokenPresent={}", refreshToken != null);

        ResponseCookie accessCookie = cookieService.createAuthCookie(accessToken);

        if (accessCookie == null) {
            log.error("❌ Failed to create access token cookie.");
            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return exchange.getResponse().setComplete();
        }

        ServerHttpResponse response = exchange.getResponse();
        response.addCookie(accessCookie);

        if (refreshToken != null && !refreshToken.isBlank()) {
            ResponseCookie refreshCookie = createRefreshTokenCookie(refreshToken);
            response.addCookie(refreshCookie);
        } else {
            log.warn("⚠️ No refresh token received from Keycloak. Session will not be refreshable.");
        }

        log.info("➡️  Redirecting user to frontend: {}", props.getRedirectAfterLogin());

        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(URI.create(props.getRedirectAfterLogin()));

        return response.setComplete();
    }

    /**
     * Logout requirements:
     * - NO Keycloak UI confirmation
     * - User lands directly on public page
     *
     * Strategy:
     * 1) Backchannel POST to Keycloak logout endpoint with refresh_token
     *    -> Keycloak session is terminated server-side
     * 2) Clear Skillshub cookies
     * 3) Redirect to public page
     */
    public Mono<Void> performLogout(ServerWebExchange exchange) {
        log.info("🔓 Logout requested → Backchannel Keycloak logout + clearing cookies…");

        String refreshCookieName = props.getCookieName() + REFRESH_COOKIE_SUFFIX;
        var refreshCookie = exchange.getRequest().getCookies().getFirst(refreshCookieName);
        String refreshToken = refreshCookie != null ? refreshCookie.getValue() : null;

        Mono<Void> keycloakLogoutMono = Mono.empty();
        if (refreshToken != null && !refreshToken.isBlank()) {
            keycloakLogoutMono = backchannelLogoutKeycloak(refreshToken)
                    .doOnSuccess(v -> log.info("✅ Keycloak backchannel logout OK"))
                    .onErrorResume(e -> {
                        // English comment: do not block user logout UX if Keycloak call fails; we still clear cookies.
                        log.warn("⚠️ Keycloak backchannel logout failed: {}", e.getMessage());
                        return Mono.empty();
                    });
        } else {
            log.warn("⚠️ No refresh token cookie found → skipping Keycloak backchannel logout (cookies will still be cleared).");
        }

        return keycloakLogoutMono.then(Mono.defer(() -> {
            ServerHttpResponse response = exchange.getResponse();

            ResponseCookie clearAccessCookie = cookieService.clearAuthCookie();
            response.addCookie(clearAccessCookie);

            ResponseCookie clearRefreshCookie = clearRefreshTokenCookie();
            response.addCookie(clearRefreshCookie);

            log.info("➡️  Redirecting user after logout: {}", props.getRedirectAfterLogout());

            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(URI.create(props.getRedirectAfterLogout()));

            return response.setComplete();
        }));
    }

    private Mono<Void> backchannelLogoutKeycloak(String refreshToken) {
        // Keycloak endpoint: /realms/{realm}/protocol/openid-connect/logout
        String logoutUrl = keycloakBaseUrl + "/realms/" + realm + "/protocol/openid-connect/logout";

        return webClient
                .post()
                .uri(logoutUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("client_id", gatewayClientId)
                        .with("refresh_token", refreshToken))
                .retrieve()
                .toBodilessEntity()
                .then();
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