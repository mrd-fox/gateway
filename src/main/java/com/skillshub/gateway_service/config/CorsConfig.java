package com.skillshub.gateway_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;


@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        //  Allowed origins (adjust depending on your environment)
        config.setAllowedOrigins(List.of(
                "http://localhost:5173",   // local frontend
                "http://127.0.0.1:5173"
        ));

        //  Allowed HTTP methods
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));

        //  Allowed headers
        config.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Origin",
                "Accept"
        ));

        //  Allow sending credentials (cookies, authorization headers)
        config.setAllowCredentials(true);

        //  Expose custom headers (optional)
        config.setExposedHeaders(List.of(
                "X-User-Email",
                "X-User-Roles",
                "X-Service",
                "X-Gateway"
        ));

        // Apply configuration to all routes
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }
}