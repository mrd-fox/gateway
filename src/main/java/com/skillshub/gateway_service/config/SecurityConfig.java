package com.skillshub.gateway_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

        // Configure JWT converter if we need custom role mapping (optional)
        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        var reactiveJwtConverter = new ReactiveJwtAuthenticationConverterAdapter(jwtConverter);

        return http
                // Disable CSRF because Gateway is stateless and acts as a proxy
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                // Authorize exchanges based on path
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/actuator/**").permitAll()   // health/info endpoints
                        .pathMatchers("/public/**").permitAll()     // public routes if needed
                        .anyExchange().authenticated()               // all others need valid JWT
                )

                // Enable JWT authentication with Keycloak as the resource server
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(reactiveJwtConverter))
                )

                // Build the final security chain
                .build();
    }
}
