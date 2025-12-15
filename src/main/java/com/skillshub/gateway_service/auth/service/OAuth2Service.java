package com.skillshub.gateway_service.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * OAuth2Service handles the "authorization_code" exchange with Keycloak.
 * <p>
 * Steps:
 * 1. Receive authorization code + state from callback
 * 2. Rebuild the AuthorizationRequest + AuthorizationResponse
 * 3. Build an OAuth2AuthorizeRequest
 * 4. Delegate the actual token exchange to ReactiveOAuth2AuthorizedClientManager
 * <p>
 * Result:
 * Returns an OAuth2AuthorizedClient containing AccessToken + RefreshToken.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2Service {

    private final ReactiveClientRegistrationRepository registrationRepository;
    private final WebClient webClient = WebClient.builder().build();

    public Mono<Map<String, Object>> exchangeAuthorizationCode(String code, String redirectUri) {

        return registrationRepository.findByRegistrationId("keycloak")
                .switchIfEmpty(Mono.error(new IllegalStateException("Keycloak client registration not found")))
                .flatMap(clientRegistration -> {

                    String tokenUri = clientRegistration.getProviderDetails()
                            .getTokenUri();

                    // Manual token request, per OAuth2 spec
                    return webClient.post()
                            .uri(tokenUri)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .bodyValue(Map.of(
                                    OAuth2ParameterNames.GRANT_TYPE, "authorization_code",
                                    OAuth2ParameterNames.CODE, code,
                                    OAuth2ParameterNames.REDIRECT_URI, redirectUri,
                                    OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId()
                            ))
                            .retrieve()
                            .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                            })
                            .doOnNext(resp -> log.info("🔐 Token received from Keycloak"))
                            .doOnError(err -> log.error("❌ Failed to exchange code for token", err));
                });
    }
}