package com.skillshub.gateway_service.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Configuration
public class CorsConfig {

    private static final List<String> DEV_ORIGINS = List.of(
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://host.docker.internal:5173"
    );

    private final Environment environment;

    public CorsConfig(Environment environment) {
        this.environment = environment;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // Read production origins from ALLOWED_ORIGIN_1, ALLOWED_ORIGIN_2, ...
        List<String> origins = new ArrayList<>();
        for (int i = 1; ; i++) {
            String origin = environment.getProperty("ALLOWED_ORIGIN_" + i);
            if (origin == null || origin.isBlank()) break;
            origins.add(origin.trim());
        }

        // Fallback: if no env origins defined, use localhost dev origins
        if (origins.isEmpty()) {
            origins.addAll(DEV_ORIGINS);
        }

        log.info("CORS allowedOriginPatterns: {}", origins);

        config.setAllowedOrigins(origins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "Accept",
                "Origin",
                "X-Requested-With",
                "Cookie"
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }
}