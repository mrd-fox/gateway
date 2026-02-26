package com.skillshub.gateway_service.user.service;

import com.skillshub.gateway_service.auth.service.CookieService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * EnrollmentFacadeService:
 * Orchestrates enrollment creation without business logic.
 * <p>
 * Responsibilities:
 * - Extract authenticated user external ID from session cookie
 * - Propagate X-User-Roles header to downstream User-Service
 * - Call User-Service POST /api/users/external/{externalUserId}/enrollments/{courseId}
 * - Map 409 CONFLICT to 204 NO_CONTENT (idempotent behavior)
 * - Standardize downstream errors (ApiError format)
 */
@Slf4j
@Service
public class EnrollmentFacadeService {

    private static final String BACKEND_ENROLL_PATH = "/api/users/external/{externalUserId}/enrollments/{courseId}";
    private static final String HEADER_USER_ROLES = "X-User-Roles";

    private final CookieService cookieService;
    private final WebClient backendClient;

    public EnrollmentFacadeService(
            CookieService cookieService,
            WebClient.Builder webClientBuilder,
            @Value("${app.backend.base-url}") String backendBaseUrl
    ) {
        this.cookieService = cookieService;
        this.backendClient = webClientBuilder.baseUrl(backendBaseUrl).build();
    }

    /**
     * Enroll the authenticated user in a course.
     * Returns 204 NO_CONTENT on success or idempotent 409 mapping.
     * Returns 401 UNAUTHORIZED if session is invalid.
     * Returns 5xx on downstream failure.
     */
    public Mono<Void> enrollInCourse(ServerWebExchange exchange, String courseId) {
        log.info("➡️  EnrollmentFacadeService.enrollInCourse courseId={}", courseId);

        return cookieService.extractUserFromCookie(exchange)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized")))
                .flatMap(claims -> {
                    String externalUserId = asString(claims.get("sub"));
                    if (isBlank(externalUserId)) {
                        return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing sub claim"));
                    }

                    List<String> roles = extractRoles(claims);
                    String rolesHeader = String.join(",", roles);

                    log.debug("Enrolling user externalUserId={} in courseId={} with roles={}", externalUserId, courseId, rolesHeader);

                    return callUserServiceEnrollment(externalUserId, courseId, rolesHeader)
                            .onErrorResume(this::handleDownstreamError);
                });
    }

    private Mono<Void> callUserServiceEnrollment(String externalUserId, String courseId, String rolesHeader) {
        return backendClient.post()
                .uri(BACKEND_ENROLL_PATH, externalUserId, courseId)
                .header(HEADER_USER_ROLES, rolesHeader)
                .exchangeToMono(resp -> {
                    HttpStatus status = (HttpStatus) resp.statusCode();

                    if (status.is2xxSuccessful()) {
                        log.debug("USER_SERVICE: enrollment success externalUserId={} courseId={}", externalUserId, courseId);
                        return Mono.empty();
                    } else if (status == HttpStatus.CONFLICT) {
                        // Idempotent: already enrolled -> map to 204
                        log.debug("USER_SERVICE: enrollment already exists (409 -> 204) externalUserId={} courseId={}", externalUserId, courseId);
                        return Mono.empty();
                    } else if (status == HttpStatus.NOT_FOUND) {
                        log.warn("USER_SERVICE: resource not found externalUserId={} courseId={} status={}", externalUserId, courseId, status);
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "USER_SERVICE: resource not found (user or course)"
                        ));
                    } else if (status.is4xxClientError()) {
                        log.warn("USER_SERVICE: client error externalUserId={} courseId={} status={}", externalUserId, courseId, status);
                        return resp.createException().flatMap(Mono::error);
                    } else {
                        log.error("USER_SERVICE: server error externalUserId={} courseId={} status={}", externalUserId, courseId, status);
                        return resp.createException().flatMap(Mono::error);
                    }
                });
    }

    private Mono<Void> handleDownstreamError(Throwable err) {
        log.error("GATEWAY: enrollment failed (downstream error)", err);

        if (err instanceof ResponseStatusException rse) {
            return Mono.error(rse);
        }

        if (err instanceof WebClientResponseException wcre) {
            HttpStatus status = (HttpStatus) wcre.getStatusCode();
            String message = String.format(
                    "GATEWAY: downstream USER_SERVICE failed with status=%s, message=%s",
                    status.value(),
                    wcre.getMessage()
            );
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_GATEWAY, message, err));
        }

        return Mono.error(new ResponseStatusException(
                HttpStatus.BAD_GATEWAY,
                "GATEWAY: enrollment failed (downstream error)",
                err
        ));
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Map<String, Object> claims) {
        Object realmAccess = claims.get("realm_access");
        if (realmAccess instanceof Map) {
            Object roles = ((Map<String, Object>) realmAccess).get("roles");
            if (roles instanceof List) {
                return (List<String>) roles;
            }
        }
        return List.of();
    }

    private String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}


