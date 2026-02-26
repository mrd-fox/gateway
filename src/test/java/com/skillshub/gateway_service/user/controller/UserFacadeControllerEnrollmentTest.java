//package com.skillshub.gateway_service.user.controller;
//
//import com.skillshub.gateway_service.user.service.EnrollmentFacadeService;
//import org.junit.jupiter.api.DisplayName;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
//import org.springframework.boot.test.mock.mockito.MockBean;
//import org.springframework.http.HttpStatus;
//import org.springframework.test.context.ContextConfiguration;
//import org.springframework.test.web.reactive.server.WebTestClient;
//import org.springframework.web.server.ResponseStatusException;
//import org.springframework.web.server.ServerWebExchange;
//import reactor.core.publisher.Mono;
//
//import static org.mockito.ArgumentMatchers.any;
//import static org.mockito.ArgumentMatchers.eq;
//import static org.mockito.Mockito.*;
//
//@WebFluxTest
//@ContextConfiguration(classes = {UserFacadeController.class})
//@DisplayName("UserFacadeController - Enrollment Endpoint")
//class UserFacadeControllerEnrollmentTest {
//
//    @Autowired
//    private WebTestClient webTestClient;
//
//    @MockBean
//    private EnrollmentFacadeService enrollmentFacadeService;
//
//    // These are required by the controller but not used in enrollment tests
//    @MockBean
//    @SuppressWarnings("unused")
//    private com.skillshub.gateway_service.user.service.UserProvisioningService userProvisioningService;
//
//    @MockBean
//    @SuppressWarnings("unused")
//    private com.skillshub.gateway_service.user.service.TutorPromotionService tutorPromotionService;
//
//    private static final String COURSE_ID = "course-123";
//
//    @Test
//    @DisplayName("PUT /api/users/me/enrollments/{courseId} should return 204 on success")
//    void enrollInCourse_success_shouldReturn204() {
//        // Given
//        when(enrollmentFacadeService.enrollInCourse(any(ServerWebExchange.class), eq(COURSE_ID)))
//                .thenReturn(Mono.empty());
//
//        // When & Then
//        webTestClient.put()
//                .uri("/api/users/me/enrollments/{courseId}", COURSE_ID)
//                .exchange()
//                .expectStatus().isNoContent()
//                .expectBody().isEmpty();
//
//        verify(enrollmentFacadeService).enrollInCourse(any(ServerWebExchange.class), eq(COURSE_ID));
//    }
//
//    @Test
//    @DisplayName("PUT /api/users/me/enrollments/{courseId} should return 204 on idempotent 409")
//    void enrollInCourse_conflict_shouldReturn204() {
//        // Given - service maps 409 to empty Mono (idempotent)
//        when(enrollmentFacadeService.enrollInCourse(any(ServerWebExchange.class), eq(COURSE_ID)))
//                .thenReturn(Mono.empty());
//
//        // When & Then
//        webTestClient.put()
//                .uri("/api/users/me/enrollments/{courseId}", COURSE_ID)
//                .exchange()
//                .expectStatus().isNoContent()
//                .expectBody().isEmpty();
//
//        verify(enrollmentFacadeService).enrollInCourse(any(ServerWebExchange.class), eq(COURSE_ID));
//    }
//
//    @Test
//    @DisplayName("PUT /api/users/me/enrollments/{courseId} should return 401 when unauthorized")
//    void enrollInCourse_unauthorized_shouldReturn401() {
//        // Given
//        when(enrollmentFacadeService.enrollInCourse(any(ServerWebExchange.class), eq(COURSE_ID)))
//                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized")));
//
//        // When & Then
//        webTestClient.put()
//                .uri("/api/users/me/enrollments/{courseId}", COURSE_ID)
//                .exchange()
//                .expectStatus().isUnauthorized();
//
//        verify(enrollmentFacadeService).enrollInCourse(any(ServerWebExchange.class), eq(COURSE_ID));
//    }
//
//    @Test
//    @DisplayName("PUT /api/users/me/enrollments/{courseId} should return 404 when resource not found")
//    void enrollInCourse_notFound_shouldReturn404() {
//        // Given
//        when(enrollmentFacadeService.enrollInCourse(any(ServerWebExchange.class), eq(COURSE_ID)))
//                .thenReturn(Mono.error(new ResponseStatusException(
//                        HttpStatus.NOT_FOUND,
//                        "USER_SERVICE: resource not found (user or course)"
//                )));
//
//        // When & Then
//        webTestClient.put()
//                .uri("/api/users/me/enrollments/{courseId}", COURSE_ID)
//                .exchange()
//                .expectStatus().isNotFound();
//
//        verify(enrollmentFacadeService).enrollInCourse(any(ServerWebExchange.class), eq(COURSE_ID));
//    }
//
//    @Test
//    @DisplayName("PUT /api/users/me/enrollments/{courseId} should return 502 on downstream failure")
//    void enrollInCourse_downstreamFailure_shouldReturn502() {
//        // Given
//        when(enrollmentFacadeService.enrollInCourse(any(ServerWebExchange.class), eq(COURSE_ID)))
//                .thenReturn(Mono.error(new ResponseStatusException(
//                        HttpStatus.BAD_GATEWAY,
//                        "GATEWAY: downstream USER_SERVICE failed"
//                )));
//
//        // When & Then
//        webTestClient.put()
//                .uri("/api/users/me/enrollments/{courseId}", COURSE_ID)
//                .exchange()
//                .expectStatus().isEqualTo(HttpStatus.BAD_GATEWAY);
//
//        verify(enrollmentFacadeService).enrollInCourse(any(ServerWebExchange.class), eq(COURSE_ID));
//    }
//
//    @Test
//    @DisplayName("PUT /api/users/me/enrollments/{courseId} should accept path variable correctly")
//    void enrollInCourse_withDifferentCourseId_shouldPassCorrectly() {
//        // Given
//        String differentCourseId = "another-course-789";
//        when(enrollmentFacadeService.enrollInCourse(any(ServerWebExchange.class), eq(differentCourseId)))
//                .thenReturn(Mono.empty());
//
//        // When & Then
//        webTestClient.put()
//                .uri("/api/users/me/enrollments/{courseId}", differentCourseId)
//                .exchange()
//                .expectStatus().isNoContent();
//
//        verify(enrollmentFacadeService).enrollInCourse(any(ServerWebExchange.class), eq(differentCourseId));
//    }
//
//    @Test
//    @DisplayName("PUT /api/users/me/enrollments/{courseId} should return 500 on unexpected error")
//    void enrollInCourse_unexpectedError_shouldReturn500() {
//        // Given
//        when(enrollmentFacadeService.enrollInCourse(any(ServerWebExchange.class), eq(COURSE_ID)))
//                .thenReturn(Mono.error(new RuntimeException("Unexpected error")));
//
//        // When & Then
//        webTestClient.put()
//                .uri("/api/users/me/enrollments/{courseId}", COURSE_ID)
//                .exchange()
//                .expectStatus().is5xxServerError();
//
//        verify(enrollmentFacadeService).enrollInCourse(any(ServerWebExchange.class), eq(COURSE_ID));
//    }
//}
//
//
