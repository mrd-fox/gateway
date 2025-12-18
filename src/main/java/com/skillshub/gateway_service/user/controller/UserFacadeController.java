package com.skillshub.gateway_service.user.controller;

import com.skillshub.gateway_service.user.client.dto.InternalUserEnvelope;
import com.skillshub.gateway_service.user.client.dto.InternalUserResponse;
import com.skillshub.gateway_service.user.service.TutorPromotionService;
import com.skillshub.gateway_service.user.service.UserProvisioningService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserFacadeController {
    private final UserProvisioningService userProvisioningService;
    private final TutorPromotionService tutorPromotionService;

    @GetMapping(value = "/me", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<InternalUserEnvelope> me(ServerWebExchange exchange) {
        return userProvisioningService.getOrCreateUser(exchange);
    }

//    @PostMapping(value = "/promote-to-tutor", produces = MediaType.APPLICATION_JSON_VALUE)
//    public Mono<InternalUserEnvelope> promoteToTutor(ServerWebExchange exchange) {
//        return tutorPromotionService.promoteToTutor(exchange);
//    }

    @PostMapping(value = "/promote-to-tutor", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<InternalUserResponse>> promoteToTutor(ServerWebExchange exchange) {
        return tutorPromotionService.promoteToTutor(exchange)
                .map(body -> ResponseEntity.ok()
                        .header("X-Handled-By", "GATEWAY-FACADE")
                        .body(body));
    }
}
