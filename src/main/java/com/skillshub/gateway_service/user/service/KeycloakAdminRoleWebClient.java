package com.skillshub.gateway_service.user.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class KeycloakAdminRoleWebClient implements KeycloakAdminRoleClient {
    private final WebClient webClient;

    private final String keycloakBaseUrl;
    private final String realm;
    private final String clientId;
    private final String clientSecret;

    // Simple in-memory token cache
    private final AtomicReference<TokenState> tokenStateRef = new AtomicReference<>(null);

    public KeycloakAdminRoleWebClient(
            WebClient.Builder webClientBuilder,
            @Value("${app.keycloak.base-url}") String keycloakBaseUrl,
            @Value("${app.keycloak.realm}") String realm,
            @Value("${app.keycloak.admin.client-id}") String clientId,
            @Value("${app.keycloak.admin.client-secret}") String clientSecret
    ) {
        this.webClient = webClientBuilder.build();
        this.keycloakBaseUrl = trimTrailingSlash(keycloakBaseUrl);
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    @Override
    public Mono<Void> addRealmRoleToUser(String userId, String roleName) {
        return getRealmRoleRepresentation(roleName)
                .flatMap(roleRep -> withAdminToken(token ->
                        webClient.post()
                                .uri(keycloakBaseUrl + "/admin/realms/{realm}/users/{userId}/role-mappings/realm",
                                        realm, userId)
                                .contentType(MediaType.APPLICATION_JSON)
                                .accept(MediaType.APPLICATION_JSON)
                                .headers(h -> h.setBearerAuth(token))
                                .bodyValue(List.of(roleRep))
                                .exchangeToMono(resp -> {
                                    if (resp.statusCode().is2xxSuccessful() || resp.statusCode() == HttpStatus.NO_CONTENT) {
                                        return Mono.empty();
                                    }
                                    if (resp.statusCode() == HttpStatus.NOT_FOUND) {
                                        return Mono.error(new ResponseStatusException(
                                                HttpStatus.BAD_GATEWAY,
                                                "KEYCLOAK: user or role mapping endpoint not found"
                                        ));
                                    }
                                    return resp.createException().flatMap(Mono::error);
                                })
                ));
    }

    @Override
    public Mono<Void> removeRealmRoleFromUser(String userId, String roleName) {
        return getRealmRoleRepresentation(roleName)
                .flatMap(roleRep -> withAdminToken(token ->
                        webClient.method(HttpMethod.DELETE)
                                .uri(keycloakBaseUrl + "/admin/realms/{realm}/users/{userId}/role-mappings/realm",
                                        realm, userId)
                                .contentType(MediaType.APPLICATION_JSON)
                                .accept(MediaType.APPLICATION_JSON)
                                .headers(h -> h.setBearerAuth(token))
                                .bodyValue(List.of(roleRep))
                                .exchangeToMono(resp -> {
                                    if (resp.statusCode().is2xxSuccessful() || resp.statusCode() == HttpStatus.NO_CONTENT) {
                                        return Mono.empty();
                                    }
                                    if (resp.statusCode() == HttpStatus.NOT_FOUND) {
                                        return Mono.error(new ResponseStatusException(
                                                HttpStatus.BAD_GATEWAY,
                                                "KEYCLOAK: user or role mapping endpoint not found"
                                        ));
                                    }
                                    return resp.createException().flatMap(Mono::error);
                                })
                ));
    }

    private Mono<Map<String, Object>> getRealmRoleRepresentation(String roleName) {
        return withAdminToken(token ->
                webClient.get()
                        .uri(keycloakBaseUrl + "/admin/realms/{realm}/roles/{roleName}", realm, roleName)
                        .accept(MediaType.APPLICATION_JSON)
                        .headers(h -> h.setBearerAuth(token))
                        .exchangeToMono(resp -> {
                            if (resp.statusCode().is2xxSuccessful()) {
                                return resp.bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                                });
                            }
                            if (resp.statusCode() == HttpStatus.NOT_FOUND) {
                                return Mono.error(new ResponseStatusException(
                                        HttpStatus.BAD_GATEWAY,
                                        "KEYCLOAK: role not found: " + roleName
                                ));
                            }
                            return resp.createException().flatMap(Mono::error);
                        })
        );
    }

    private <T> Mono<T> withAdminToken(java.util.function.Function<String, Mono<T>> fn) {
        return getAdminAccessToken().flatMap(fn);
    }

    private Mono<String> getAdminAccessToken() {
        TokenState current = tokenStateRef.get();
        if (current != null && current.isValid()) {
            return Mono.just(current.accessToken());
        }

        return fetchNewAdminAccessToken()
                .map(newState -> {
                    tokenStateRef.set(newState);
                    return newState.accessToken();
                });
    }

    private Mono<TokenState> fetchNewAdminAccessToken() {
        String tokenUrl = keycloakBaseUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);

        return webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(form)
                .exchangeToMono(resp -> {
                    if (resp.statusCode().is2xxSuccessful()) {
                        return resp.bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                        });
                    }
                    return resp.createException().flatMap(Mono::error);
                })
                .flatMap(body -> {
                    Object token = body.get("access_token");
                    Object expiresIn = body.get("expires_in");

                    if (token == null || String.valueOf(token).isBlank()) {
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.BAD_GATEWAY,
                                "KEYCLOAK: missing access_token in token response"
                        ));
                    }

                    long seconds = 60L;
                    if (expiresIn != null) {
                        try {
                            seconds = Long.parseLong(String.valueOf(expiresIn));
                        } catch (Exception ignored) {
                            // ignore parsing errors, fallback to default
                        }
                    }

                    // Subtract a safety margin to avoid using a token near expiry
                    Instant expiresAt = Instant.now().plusSeconds(Math.max(10L, seconds - 20L));
                    return Mono.just(new TokenState(String.valueOf(token), expiresAt));
                });
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

    private record TokenState(String accessToken, Instant expiresAt) {
        boolean isValid() {
            return accessToken != null && !accessToken.isBlank() && Instant.now().isBefore(expiresAt);
        }
    }
}
