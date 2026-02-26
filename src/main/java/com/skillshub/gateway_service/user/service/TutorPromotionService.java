package com.skillshub.gateway_service.user.service;

import com.skillshub.gateway_service.auth.service.CookieService;
import com.skillshub.gateway_service.user.client.dto.InternalUserResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

@Slf4j
@Service
public class TutorPromotionService {

    private static final String ROLE_TUTOR = "TUTOR";

    // Single partial-update endpoint in User-Service (apply only provided fields)
    private static final String BACKEND_UPDATE_BY_EXTERNAL_ID_PATH = "/api/users/external/{externalId}";

    // Reuse same read endpoint as provisioning
    private static final String BACKEND_GET_BY_EXTERNAL_ID_PATH = "/api/users/external/{externalId}";

    private final CookieService cookieService;
    private final KeycloakAdminRoleClient keycloakAdminRoleClient;
    private final WebClient backendClient;

    public TutorPromotionService(
            CookieService cookieService,
            KeycloakAdminRoleClient keycloakAdminRoleClient,
            WebClient.Builder webClientBuilder,
            @Value("${app.backend.base-url}") String backendBaseUrl
    ) {
        this.cookieService = cookieService;
        this.keycloakAdminRoleClient = keycloakAdminRoleClient;
        this.backendClient = webClientBuilder.baseUrl(backendBaseUrl).build();
    }

    public Mono<InternalUserResponse> promoteToTutor(ServerWebExchange exchange) {
        AtomicBoolean keycloakRoleAssigned = new AtomicBoolean(false);

        return cookieService.extractUserFromCookie(exchange)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized")))
                .flatMap(claims -> {
                    String externalId = asString(claims.get("sub"));
                    if (externalId == null || externalId.isBlank()) {
                        return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized"));
                    }

                    return keycloakAdminRoleClient.addRealmRoleToUser(externalId, ROLE_TUTOR)
                            .doOnSuccess(v -> keycloakRoleAssigned.set(true))
                            .then(updateAddTutorRoleInUserService(externalId)) // <-- returns InternalUserResponse
                            .switchIfEmpty(Mono.error(new ResponseStatusException(
                                    HttpStatus.BAD_GATEWAY,
                                    "USER_SERVICE: empty response on update"
                            )))
                            .onErrorResume(err -> {
                                log.error("Promotion failed: externalId={}, role={}", externalId, ROLE_TUTOR, err);

                                if (keycloakRoleAssigned.get()) {
                                    return keycloakAdminRoleClient.removeRealmRoleFromUser(externalId, ROLE_TUTOR)
                                            .doOnError(rollbackErr -> log.warn(
                                                    "Rollback failed: externalId={}, role={}",
                                                    externalId,
                                                    ROLE_TUTOR,
                                                    rollbackErr
                                            ))
                                            .onErrorResume(rollbackErr -> Mono.empty())
                                            .then(Mono.error(mapDownstreamError(err)));
                                } else {
                                    return Mono.error(mapDownstreamError(err));
                                }
                            });
                });
    }

    private Mono<InternalUserResponse> updateAddTutorRoleInUserService(String externalId) {
        Map<String, Object> payload = Map.of("rolesToAdd", new String[]{ROLE_TUTOR});

        return backendClient.put()
                .uri(BACKEND_UPDATE_BY_EXTERNAL_ID_PATH, externalId)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(payload)
                .exchangeToMono(resp -> {
                    if (resp.statusCode().is2xxSuccessful()) {
                        return resp.bodyToMono(InternalUserResponse.class);
                    } else if (resp.statusCode() == HttpStatus.NOT_FOUND) {
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "USER_SERVICE: user not found for externalId=" + externalId
                        ));
                    } else {
                        return resp.createException().flatMap(Mono::error);
                    }
                });
    }

    private RuntimeException mapDownstreamError(Throwable err) {
        if (err instanceof ResponseStatusException rse) {
            return rse;
        } else {
            return new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "GATEWAY: promotion failed (downstream error)"
            );
        }
    }

    private String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}


