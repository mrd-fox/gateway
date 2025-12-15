package com.skillshub.gateway_service.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ReactiveClientRegistrationRepository clientRegistrationRepository;
    private final CustomOAuth2SuccessHandler customOAuth2SuccessHandler;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        return http
                .cors(Customizer.withDefaults())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                .authorizeExchange(auth -> auth
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
                        .pathMatchers(
                                "/api/auth/login",
                                "/api/auth/logout",
                                "/api/auth/me",
                                "/actuator/**"
                        ).permitAll()
                        .anyExchange().permitAll()   // Le Gateway ne protège pas les routes
                )

                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(
                                new RedirectServerAuthenticationEntryPoint("/api/auth/login")
                        )
                )

                .oauth2Login(oauth -> oauth
                        .clientRegistrationRepository(clientRegistrationRepository)
                        .authenticationSuccessHandler(customOAuth2SuccessHandler)
                )

                .build();
    }
}
