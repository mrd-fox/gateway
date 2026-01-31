package com.skillshub.gateway_service.config;

import com.skillshub.gateway_service.auth.service.SessionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomOAuth2SuccessHandler implements ServerAuthenticationSuccessHandler {

    private final SessionService sessionService;
    private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange,
                                              Authentication authentication) {

        log.info("🔐 OAuth2 authentication succeeded. Extracting ID Token…");

        if (!(authentication instanceof OAuth2AuthenticationToken oauth)) {
            log.error("❌ Unexpected authentication type: {}", authentication.getClass().getName());
            return webFilterExchange.getExchange().getResponse().setComplete();
        }


        return authorizedClientService
                .loadAuthorizedClient(
                        oauth.getAuthorizedClientRegistrationId(),
                        oauth.getName()
                )
                .flatMap(client -> {

                    if (client == null || client.getAccessToken() == null) {
                        log.error("❌ No OAuth2 access token available");
                        return webFilterExchange.getExchange().getResponse().setComplete();
                    }

                    String accessToken = client.getAccessToken().getTokenValue();
                    log.info("🔑 Access Token extracted successfully.");

                    return sessionService.handleLoginSuccess(
                            accessToken,
                            webFilterExchange.getExchange()
                    );
                });
    }
}