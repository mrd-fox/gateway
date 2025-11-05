package com.skillshub.gateway_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        var reactiveJwtConverter = new ReactiveJwtAuthenticationConverterAdapter(jwtConverter);

        return http
                // ✅ Active CORS mais le délègue au bloc globalcors de la Gateway
                .cors(Customizer.withDefaults())

                // ✅ Désactive CSRF
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                // ✅ Autorise les préflights OPTIONS (sinon 401)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
                        .pathMatchers("/actuator/**").permitAll()
                        .pathMatchers("/public/**").permitAll()
                        .anyExchange().authenticated()
                )

                // ✅ Authentification JWT via Keycloak
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(reactiveJwtConverter))
                )

                .build();
    }
}
