package com.skillshub.gateway_service.auth.controller;

import com.skillshub.gateway_service.auth.service.AuthMeService;
import com.skillshub.gateway_service.auth.service.SessionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * AuthController:
 * Ultra-thin HTTP adapter for Gateway authentication flow.
 * <p>
 * All logic is delegated to SessionService.
 * The controller only binds HTTP routes to service actions.
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final SessionService sessionService;
    private final AuthMeService authMeService;

    /**
     * Start OAuth2 login (redirect to Keycloak).
     */
    @GetMapping("/login")
    public Mono<Void> login(ServerWebExchange exchange) {
        log.info("➡️  /api/auth/login");
        return sessionService.performLogin(exchange);
    }

    /**
     * Logout user → clear cookie → redirect frontend.
     * GET is required because browser redirection happens via GET.
     */
    @GetMapping("/logout")
    public Mono<Void> logout(ServerWebExchange exchange) {
        log.info("➡️  /api/auth/logout");
        return sessionService.performLogout(exchange);
    }

    /**
     * Return decoded JWT claims for the authenticated user.
     */
    @GetMapping("/me")
    public Mono<Map<String, Object>> me(ServerWebExchange exchange) {
        log.info("➡️  /api/auth/me");
        return authMeService.me(exchange);
    }
}