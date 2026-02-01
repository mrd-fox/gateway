package com.skillshub.gateway_service.auth.filter;

import com.skillshub.gateway_service.auth.AuthCookieProperties;
import com.skillshub.gateway_service.auth.service.CookieService;
import com.skillshub.gateway_service.auth.service.JwtDecoderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * AuthCookieWebFilter:
 * - Reads Access Token (AT) from cookie
 * - Validates JWT signature + expiration + issuer
 * - Injects authentication into reactive SecurityContext
 *
 * Refresh behavior:
 * - If AT is expired, tries refresh with Refresh Token (RT) cookie using Keycloak token endpoint
 * - On refresh success: rewrites cookies and continues request as authenticated
 * - On refresh failure: clears cookies and returns 401 to force re-login
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthCookieWebFilter implements WebFilter {

    private static final String REFRESH_COOKIE_SUFFIX = "_RT";

    private static final PathPattern AUTH_LOGIN_PATH =
            PathPatternParser.defaultInstance.parse("/api/auth/login");
    private static final PathPattern AUTH_LOGOUT_PATH =
            PathPatternParser.defaultInstance.parse("/api/auth/logout");
    private static final PathPattern OAUTH2_AUTH_PATH =
            PathPatternParser.defaultInstance.parse("/oauth2/**");
    private static final PathPattern OAUTH2_CALLBACK_PATH =
            PathPatternParser.defaultInstance.parse("/login/oauth2/**");
    private static final PathPattern ACTUATOR_PATH =
            PathPatternParser.defaultInstance.parse("/actuator/**");

    private final JwtDecoderService jwtDecoderService;
    private final CookieService cookieService;
    private final AuthCookieProperties props;
    private final WebClient.Builder webClientBuilder;

    @org.springframework.beans.factory.annotation.Value("${spring.security.oauth2.client.provider.keycloak.token-uri}")
    private String keycloakTokenUri;

    @org.springframework.beans.factory.annotation.Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String keycloakClientId;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        PathContainer path = exchange.getRequest().getPath().pathWithinApplication();

        if (shouldBypass(path)) {
            return chain.filter(exchange);
        }

        ServerHttpRequest request = exchange.getRequest();

        String accessCookieName = props.getCookieName();
        String refreshCookieName = props.getCookieName() + REFRESH_COOKIE_SUFFIX;

        HttpCookie accessCookie = request.getCookies().getFirst(accessCookieName);
        if (accessCookie == null || accessCookie.getValue().isBlank()) {
            // No session -> proceed as anonymous
            return chain.filter(exchange);
        }

        String accessToken = accessCookie.getValue();

        // 1) Try normal JWT validation
        Map<String, Object> claims;
        try {
            claims = jwtDecoderService.decodeJwt(accessToken);
            return continueAuthenticated(exchange, chain, claims);
        } catch (Exception e) {
            if (!isExpiredJwt(e)) {
                log.warn("⚠️ Invalid JWT cookie (not expired). Will clear cookies and return 401. reason={}", safeMsg(e));
                return clearCookiesAndUnauthorized(exchange);
            }
        }

        // 2) If expired -> try refresh
        HttpCookie refreshCookie = request.getCookies().getFirst(refreshCookieName);
        if (refreshCookie == null || refreshCookie.getValue().isBlank()) {
            log.info("🔒 Access token expired and no refresh token found -> 401");
            return clearCookiesAndUnauthorized(exchange);
        }

        String refreshToken = refreshCookie.getValue();

        return refreshAccessToken(refreshToken)
                .flatMap(tokenResponse -> {
                    String newAccessToken = (String) tokenResponse.get("access_token");
                    String newRefreshToken = (String) tokenResponse.get("refresh_token"); // may be null if no rotation

                    if (newAccessToken == null || newAccessToken.isBlank()) {
                        log.warn("⚠️ Refresh response missing access_token -> 401");
                        return clearCookiesAndUnauthorized(exchange);
                    }

                    // Rewrite cookies
                    ResponseCookie newAccessCookie = cookieService.createAuthCookie(newAccessToken);
                    exchange.getResponse().addCookie(newAccessCookie);

                    if (newRefreshToken != null && !newRefreshToken.isBlank()) {
                        ResponseCookie rtCookie = createRefreshTokenCookie(refreshCookieName, newRefreshToken);
                        exchange.getResponse().addCookie(rtCookie);
                    }

                    // Decode new token and continue authenticated
                    Map<String, Object> refreshedClaims;
                    try {
                        refreshedClaims = jwtDecoderService.decodeJwt(newAccessToken);
                    } catch (Exception ex) {
                        log.warn("⚠️ Refreshed access token invalid -> 401. reason={}", safeMsg(ex));
                        return clearCookiesAndUnauthorized(exchange);
                    }

                    return continueAuthenticated(exchange, chain, refreshedClaims);
                })
                .onErrorResume(err -> {
                    log.info("🔒 Refresh failed -> forcing re-login. reason={}", safeMsg(err));
                    return clearCookiesAndUnauthorized(exchange);
                });
    }

    private boolean shouldBypass(PathContainer path) {
        return AUTH_LOGIN_PATH.matches(path)
                || AUTH_LOGOUT_PATH.matches(path)
                || OAUTH2_AUTH_PATH.matches(path)
                || OAUTH2_CALLBACK_PATH.matches(path)
                || ACTUATOR_PATH.matches(path);
    }

    private Mono<Void> continueAuthenticated(ServerWebExchange exchange, WebFilterChain chain, Map<String, Object> claims) {

        List<String> roles = extractRoles(claims);

        AbstractAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        claims,
                        null,
                        roles.stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toSet())
                );

        return Mono.deferContextual(ctx -> chain.filter(exchange))
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
    }

    private Mono<Map<String, Object>> refreshAccessToken(String refreshToken) {

        String tokenUrl = keycloakTokenUri;

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("client_id", keycloakClientId);
        form.add("refresh_token", refreshToken);

        WebClient webClient = webClientBuilder.build();

        return webClient.post()
                .uri(URI.create(tokenUrl))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(form)
                .exchangeToMono(resp -> {
                    if (resp.statusCode().is2xxSuccessful()) {
                        return resp.bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {});
                    }
                    if (resp.statusCode() == HttpStatus.BAD_REQUEST || resp.statusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new IllegalStateException("Refresh token rejected by Keycloak"));
                    }
                    return resp.createException().flatMap(Mono::error);
                });
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Map<String, Object> claims) {
        try {
            Map<String, Object> realmAccess =
                    (Map<String, Object>) claims.get("realm_access");

            if (realmAccess == null) {
                return List.of();
            }

            return (List<String>) realmAccess.getOrDefault("roles", List.of());
        } catch (Exception e) {
            log.warn("⚠️ Failed to extract roles from JWT", e);
            return List.of();
        }
    }

    private Mono<Void> clearCookiesAndUnauthorized(ServerWebExchange exchange) {

        ServerHttpResponse response = exchange.getResponse();

        // Clear AT cookie using existing service
        ResponseCookie clearAccess = cookieService.clearAuthCookie();
        response.addCookie(clearAccess);

        // Clear RT cookie (same flags as props)
        String refreshCookieName = props.getCookieName() + REFRESH_COOKIE_SUFFIX;
        ResponseCookie clearRefresh = clearRefreshTokenCookie(refreshCookieName);
        response.addCookie(clearRefresh);

        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }

    private ResponseCookie createRefreshTokenCookie(String refreshCookieName, String refreshToken) {

        ResponseCookie.ResponseCookieBuilder builder =
                ResponseCookie.from(refreshCookieName, refreshToken)
                        .httpOnly(true)
                        .secure(props.isCookieSecure())
                        .path("/")
                        .sameSite(props.getCookieSameSite())
                        // We intentionally keep RT cookie long enough; Keycloak session policy remains the real limiter
                        .maxAge(7 * 24 * 60 * 60);

        if (props.getCookieDomain() != null && !props.getCookieDomain().isBlank()) {
            builder.domain(props.getCookieDomain());
        }

        return builder.build();
    }

    private ResponseCookie clearRefreshTokenCookie(String refreshCookieName) {

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

    private boolean isExpiredJwt(Exception e) {
        String msg = safeMsg(e);
        return msg.contains("Expired JWT token");
    }

    private String safeMsg(Throwable t) {
        if (t == null) {
            return "";
        }
        String m = t.getMessage();
        return m == null ? "" : m;
    }
}