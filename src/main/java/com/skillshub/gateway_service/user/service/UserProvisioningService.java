package com.skillshub.gateway_service.user.service;

import com.skillshub.gateway_service.auth.service.CookieService;
import com.skillshub.gateway_service.user.client.dto.InternalUserEnvelope;
import com.skillshub.gateway_service.user.client.dto.InternalUserResponse;
import com.skillshub.gateway_service.user.command.UserProvisioningCommand;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Service
public class UserProvisioningService {
    // TODO: align with your User-Service endpoints (direct call to backend, not through Gateway routes)
    private static final String BACKEND_GET_BY_EXTERNAL_ID_PATH = "/api/users/external/{externalId}";
    private static final String BACKEND_CREATE_PATH = "/api/users/create";

    private static final String H_USER_ID = "X-User-Id";
    private static final String H_USER_EMAIL = "X-User-Email";
    private static final String H_USER_ROLES = "X-User-Roles";
    private static final String H_USER_FIRSTNAME = "X-User-FirstName";
    private static final String H_USER_LASTNAME = "X-User-LastName";
    private static final String H_USER_ADDRESS = "X-User-Address";
    private static final String H_USER_CITY = "X-User-City";
    private static final String H_USER_COUNTRY = "X-User-Country";
    private static final String H_USER_POSTAL = "X-User-PostalCode";
    private static final String H_USER_PHONE = "X-User-PhoneNumber";
    private static final List<String> ALLOWED_ROLES = List.of("STUDENT", "TUTOR", "ADMIN");

    private final CookieService cookieService;
    private final WebClient webClient;

    public UserProvisioningService(
            CookieService cookieService,
            WebClient.Builder webClientBuilder,
            @Value("${app.backend.base-url}") String backendBaseUrl
    ) {
        this.cookieService = cookieService;
        this.webClient = webClientBuilder.baseUrl(backendBaseUrl).build();
    }

    public Mono<InternalUserEnvelope> getOrCreateUser(ServerWebExchange exchange) {
        return cookieService.extractUserFromCookie(exchange)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized")))
                .flatMap(claims -> {
                    UserProvisioningCommand command = buildCommandFromClaims(claims);
                    String externalId = command.getExternalId().toString();

                    return fetchByExternalId(externalId)
                            .map(user -> new InternalUserEnvelope(false, user))
                            .switchIfEmpty(
                                    createUserWithHeaders(command, claims)
                                            .then(Mono.defer(() -> fetchByExternalId(externalId)))
                                            .switchIfEmpty(Mono.error(new ResponseStatusException(
                                                    HttpStatus.INTERNAL_SERVER_ERROR,
                                                    "User creation attempted but user still not found"
                                            )))
                                            .map(user -> new InternalUserEnvelope(true, user))
                            );
                });
    }

    private Mono<InternalUserResponse> fetchByExternalId(String externalId) {
        return webClient.get()
                .uri(BACKEND_GET_BY_EXTERNAL_ID_PATH, externalId)
                .accept(MediaType.APPLICATION_JSON)
                .exchangeToMono(resp -> {
                    if (resp.statusCode() == HttpStatus.NOT_FOUND) {
                        return Mono.empty();
                    } else if (resp.statusCode().is2xxSuccessful()) {
                        return resp.bodyToMono(InternalUserResponse.class);
                    } else {
                        return resp.createException().flatMap(Mono::error);
                    }
                });
    }


    private UserProvisioningCommand buildCommandFromClaims(Map<String, Object> claims) {
        String sub = asString(claims.get("sub"));
        String email = asString(claims.get("email"));
        List<String> roles = extractRealmRoles(claims);

        // optional now
        String firstName = asString(claims.get("given_name"));
        String lastName = asString(claims.get("family_name"));


        if (isBlank(firstName) || isBlank(lastName)) {
            String fullName = asString(claims.get("name"));
            if (!isBlank(fullName)) {
                String[] parts = fullName.trim().split("\\s+", 2);
                if (isBlank(firstName)) {
                    firstName = parts[0];
                }
                if (isBlank(lastName) && parts.length > 1) {
                    lastName = parts[1];
                }
            }
        }

        return UserProvisioningCommand.fromClaims(sub, email, firstName, lastName, roles);
    }


    @SuppressWarnings("unchecked")
    private List<String> extractRealmRoles(Map<String, Object> claims) {
        try {
            Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
            if (realmAccess == null) {
                return List.of("STUDENT");
            }

            List<String> roles = (List<String>) realmAccess.getOrDefault("roles", List.of());

            List<String> normalized = roles.stream()
                    .map(String::valueOf)
                    .map(String::trim)
                    .filter(r -> !r.isBlank())
                    .map(String::toUpperCase)
                    .filter(ALLOWED_ROLES::contains)
                    .distinct()
                    .toList();

            if (normalized.isEmpty()) {
                return List.of("STUDENT");
            }
            return normalized;

        } catch (Exception e) {
            return List.of("STUDENT");
        }
    }

    private String asString(Object value) {
        if (value == null) {
            return null;
        } else {
            return String.valueOf(value);
        }
    }

    private Mono<Void> createUserWithHeaders(UserProvisioningCommand command, Map<String, Object> claims) {

        String externalId = command.getExternalId().toString();

        // Optional claims (Keycloak) – best effort
        String firstName = asString(claims.get("given_name"));
        String lastName = asString(claims.get("family_name"));
        String address = null;
        String city = null;
        String country = null;
        String postalCode = null;
        String phoneNumber = null;

        // Roles header is comma-separated
        String rolesHeader = String.join(",", command.getRoles());

        return webClient.post()
                .uri(BACKEND_CREATE_PATH) // "/api/users/create"
                .accept(MediaType.APPLICATION_JSON)
                .headers(h -> {
                    // Required
                    h.set(H_USER_ID, externalId);
                    h.set(H_USER_EMAIL, command.getEmail());
                    h.set(H_USER_ROLES, rolesHeader);

                    // Optional (only set if present)
                    setIfPresent(h, H_USER_FIRSTNAME, firstName);
                    setIfPresent(h, H_USER_LASTNAME, lastName);
                    setIfPresent(h, H_USER_ADDRESS, address);
                    setIfPresent(h, H_USER_CITY, city);
                    setIfPresent(h, H_USER_COUNTRY, country);
                    setIfPresent(h, H_USER_POSTAL, postalCode);
                    setIfPresent(h, H_USER_PHONE, phoneNumber);
                })
                .exchangeToMono(resp -> {
                    if (resp.statusCode().is2xxSuccessful()) {
                        return Mono.<Void>empty();
                    } else if (resp.statusCode() == HttpStatus.CONFLICT) {
                        // If you later add 409 on unique constraint, treat as idempotent
                        return Mono.<Void>empty();
                    } else {
                        return resp.createException().flatMap(Mono::error);
                    }
                });
    }

    private void setIfPresent(org.springframework.http.HttpHeaders h, String name, String value) {
        if (value == null || value.isBlank()) {
            return;
        }
        h.set(name, value);
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}


