package com.skillshub.gateway_service.user.service;

import com.skillshub.gateway_service.auth.service.CookieService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("EnrollmentFacadeService")
class EnrollmentFacadeServiceTest {

    private static final String EXTERNAL_USER_ID = "keycloak-user-123";
    private static final String COURSE_ID = "course-456";
    private static final String BACKEND_BASE_URL = "http://localhost:10020";

    @Mock
    private CookieService cookieService;

    @Mock
    private WebClient.Builder webClientBuilder;

    @Mock
    private WebClient webClient;

    @Mock
    private WebClient.RequestBodyUriSpec requestBodyUriSpec;

    private EnrollmentFacadeService service;
    private MockServerWebExchange exchange;

    @BeforeEach
    void setUp() {
        MockServerHttpRequest request = MockServerHttpRequest.put("/api/users/me/enrollments/" + COURSE_ID).build();
        exchange = MockServerWebExchange.from(request);

        when(webClientBuilder.baseUrl(BACKEND_BASE_URL)).thenReturn(webClientBuilder);
        when(webClientBuilder.build()).thenReturn(webClient);

        service = new EnrollmentFacadeService(cookieService, webClientBuilder, BACKEND_BASE_URL);
    }

    @Nested
    @DisplayName("enrollInCourse()")
    class EnrollInCourseTests {

        @Test
        @DisplayName("should return 204 NO_CONTENT when enrollment succeeds")
        void enrollInCourse_success_shouldReturn204() {
            // Given
            Map<String, Object> claims = Map.of(
                    "sub", EXTERNAL_USER_ID,
                    "email", "user@test.com",
                    "realm_access", Map.of("roles", List.of("STUDENT"))
            );

            ClientResponse mockResponse = mock(ClientResponse.class);
            when(mockResponse.statusCode()).thenReturn(HttpStatus.CREATED);

            when(cookieService.extractUserFromCookie(exchange)).thenReturn(Mono.just(claims));
            when(webClient.post()).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.uri(anyString(), anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.header(anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.exchangeToMono(any())).thenAnswer(invocation -> {
                Function<ClientResponse, Mono<Void>> function = invocation.getArgument(0);
                return function.apply(mockResponse);
            });

            // When
            Void result = service.enrollInCourse(exchange, COURSE_ID).block();

            // Then
            assertNull(result);
            verify(cookieService).extractUserFromCookie(exchange);
            verify(webClient).post();
        }

        @Test
        @DisplayName("should return 204 NO_CONTENT when enrollment already exists (409 -> 204 mapping)")
        void enrollInCourse_conflict_shouldMapTo204() {
            // Given
            Map<String, Object> claims = Map.of(
                    "sub", EXTERNAL_USER_ID,
                    "email", "user@test.com",
                    "realm_access", Map.of("roles", List.of("STUDENT"))
            );

            ClientResponse mockResponse = mock(ClientResponse.class);
            when(mockResponse.statusCode()).thenReturn(HttpStatus.CONFLICT);

            when(cookieService.extractUserFromCookie(exchange)).thenReturn(Mono.just(claims));
            when(webClient.post()).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.uri(anyString(), anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.header(anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.exchangeToMono(any())).thenAnswer(invocation -> {
                Function<ClientResponse, Mono<Void>> function = invocation.getArgument(0);
                return function.apply(mockResponse);
            });

            // When
            Void result = service.enrollInCourse(exchange, COURSE_ID).block();

            // Then
            assertNull(result);
            verify(cookieService).extractUserFromCookie(exchange);
            verify(webClient).post();
        }

        @Test
        @DisplayName("should return 401 UNAUTHORIZED when cookie is missing")
        void enrollInCourse_noCookie_shouldReturn401() {
            // Given
            when(cookieService.extractUserFromCookie(exchange)).thenReturn(Mono.empty());

            // When & Then
            ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                    service.enrollInCourse(exchange, COURSE_ID).block()
            );

            assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
            assertTrue(exception.getReason() != null && exception.getReason().contains("Unauthorized"));
            verify(cookieService).extractUserFromCookie(exchange);
            verify(webClient, never()).post();
        }

        @Test
        @DisplayName("should return 401 UNAUTHORIZED when sub claim is missing")
        void enrollInCourse_noSubClaim_shouldReturn401() {
            // Given
            Map<String, Object> claims = Map.of(
                    "email", "user@test.com",
                    "realm_access", Map.of("roles", List.of("STUDENT"))
            );

            when(cookieService.extractUserFromCookie(exchange)).thenReturn(Mono.just(claims));

            // When & Then
            ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                    service.enrollInCourse(exchange, COURSE_ID).block()
            );

            assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
            assertTrue(exception.getReason() != null && exception.getReason().contains("Missing sub claim"));
            verify(cookieService).extractUserFromCookie(exchange);
            verify(webClient, never()).post();
        }

        @Test
        @DisplayName("should return 404 NOT_FOUND when downstream returns 404")
        void enrollInCourse_downstreamNotFound_shouldReturn404() {
            // Given
            Map<String, Object> claims = Map.of(
                    "sub", EXTERNAL_USER_ID,
                    "email", "user@test.com",
                    "realm_access", Map.of("roles", List.of("STUDENT"))
            );

            ClientResponse mockResponse = mock(ClientResponse.class);
            when(mockResponse.statusCode()).thenReturn(HttpStatus.NOT_FOUND);

            when(cookieService.extractUserFromCookie(exchange)).thenReturn(Mono.just(claims));
            when(webClient.post()).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.uri(anyString(), anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.header(anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.exchangeToMono(any())).thenAnswer(invocation -> {
                Function<ClientResponse, Mono<Void>> function = invocation.getArgument(0);
                return function.apply(mockResponse);
            });

            // When & Then
            ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                    service.enrollInCourse(exchange, COURSE_ID).block()
            );

            assertEquals(HttpStatus.NOT_FOUND, exception.getStatusCode());
            assertTrue(exception.getReason() != null && exception.getReason().contains("USER_SERVICE"));
            verify(cookieService).extractUserFromCookie(exchange);
            verify(webClient).post();
        }

        @Test
        @DisplayName("should return 502 BAD_GATEWAY when downstream returns 500")
        void enrollInCourse_downstreamServerError_shouldReturn502() {
            // Given
            Map<String, Object> claims = Map.of(
                    "sub", EXTERNAL_USER_ID,
                    "email", "user@test.com",
                    "realm_access", Map.of("roles", List.of("STUDENT"))
            );

            ClientResponse mockResponse = mock(ClientResponse.class);
            when(mockResponse.statusCode()).thenReturn(HttpStatus.INTERNAL_SERVER_ERROR);
            when(mockResponse.createException()).thenReturn(
                    Mono.error(WebClientResponseException.create(
                            500,
                            "Internal Server Error",
                            null,
                            null,
                            null
                    ))
            );

            when(cookieService.extractUserFromCookie(exchange)).thenReturn(Mono.just(claims));
            when(webClient.post()).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.uri(anyString(), anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.header(anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.exchangeToMono(any())).thenAnswer(invocation -> {
                Function<ClientResponse, Mono<Void>> function = invocation.getArgument(0);
                return function.apply(mockResponse);
            });

            // When & Then
            ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                    service.enrollInCourse(exchange, COURSE_ID).block()
            );

            assertEquals(HttpStatus.BAD_GATEWAY, exception.getStatusCode());
            assertTrue(exception.getReason() != null && exception.getReason().contains("downstream USER_SERVICE failed"));
            verify(cookieService).extractUserFromCookie(exchange);
            verify(webClient).post();
        }

        @Test
        @DisplayName("should propagate X-User-Roles header to downstream")
        void enrollInCourse_shouldPropagateRolesHeader() {
            // Given
            Map<String, Object> claims = Map.of(
                    "sub", EXTERNAL_USER_ID,
                    "email", "user@test.com",
                    "realm_access", Map.of("roles", List.of("STUDENT", "TUTOR"))
            );

            ClientResponse mockResponse = mock(ClientResponse.class);
            when(mockResponse.statusCode()).thenReturn(HttpStatus.CREATED);

            when(cookieService.extractUserFromCookie(exchange)).thenReturn(Mono.just(claims));
            when(webClient.post()).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.uri(anyString(), anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.header(anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.exchangeToMono(any())).thenAnswer(invocation -> {
                Function<ClientResponse, Mono<Void>> function = invocation.getArgument(0);
                return function.apply(mockResponse);
            });

            // When
            service.enrollInCourse(exchange, COURSE_ID).block();

            // Then
            ArgumentCaptor<String> headerNameCaptor = ArgumentCaptor.forClass(String.class);
            ArgumentCaptor<String> headerValueCaptor = ArgumentCaptor.forClass(String.class);
            verify(requestBodyUriSpec).header(headerNameCaptor.capture(), headerValueCaptor.capture());

            assertThat(headerNameCaptor.getValue()).isEqualTo("X-User-Roles");
            assertThat(headerValueCaptor.getValue()).contains("STUDENT");
            assertThat(headerValueCaptor.getValue()).contains("TUTOR");
        }

        @Test
        @DisplayName("should handle empty roles list gracefully")
        void enrollInCourse_withEmptyRoles_shouldSucceed() {
            // Given
            Map<String, Object> claims = Map.of(
                    "sub", EXTERNAL_USER_ID,
                    "email", "user@test.com",
                    "realm_access", Map.of("roles", List.of())
            );

            ClientResponse mockResponse = mock(ClientResponse.class);
            when(mockResponse.statusCode()).thenReturn(HttpStatus.CREATED);

            when(cookieService.extractUserFromCookie(exchange)).thenReturn(Mono.just(claims));
            when(webClient.post()).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.uri(anyString(), anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.header(anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.exchangeToMono(any())).thenAnswer(invocation -> {
                Function<ClientResponse, Mono<Void>> function = invocation.getArgument(0);
                return function.apply(mockResponse);
            });

            // When
            Void result = service.enrollInCourse(exchange, COURSE_ID).block();

            // Then
            assertNull(result);
            verify(requestBodyUriSpec).header(eq("X-User-Roles"), eq(""));
        }

        @Test
        @DisplayName("should handle claims without realm_access gracefully")
        void enrollInCourse_withoutRealmAccess_shouldSucceed() {
            // Given
            Map<String, Object> claims = Map.of(
                    "sub", EXTERNAL_USER_ID,
                    "email", "user@test.com"
            );

            ClientResponse mockResponse = mock(ClientResponse.class);
            when(mockResponse.statusCode()).thenReturn(HttpStatus.CREATED);

            when(cookieService.extractUserFromCookie(exchange)).thenReturn(Mono.just(claims));
            when(webClient.post()).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.uri(anyString(), anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.header(anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.exchangeToMono(any())).thenAnswer(invocation -> {
                Function<ClientResponse, Mono<Void>> function = invocation.getArgument(0);
                return function.apply(mockResponse);
            });

            // When
            Void result = service.enrollInCourse(exchange, COURSE_ID).block();

            // Then
            assertNull(result);
            verify(requestBodyUriSpec).header(eq("X-User-Roles"), eq(""));
        }

        @Test
        @DisplayName("should return 502 BAD_GATEWAY on generic downstream error")
        void enrollInCourse_genericError_shouldReturn502() {
            // Given
            Map<String, Object> claims = Map.of(
                    "sub", EXTERNAL_USER_ID,
                    "email", "user@test.com",
                    "realm_access", Map.of("roles", List.of("STUDENT"))
            );

            when(cookieService.extractUserFromCookie(exchange)).thenReturn(Mono.just(claims));
            when(webClient.post()).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.uri(anyString(), anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.header(anyString(), anyString())).thenReturn(requestBodyUriSpec);
            when(requestBodyUriSpec.exchangeToMono(any())).thenReturn(
                    Mono.error(new RuntimeException("Network error"))
            );

            // When & Then
            ResponseStatusException exception = assertThrows(ResponseStatusException.class, () ->
                    service.enrollInCourse(exchange, COURSE_ID).block()
            );

            assertEquals(HttpStatus.BAD_GATEWAY, exception.getStatusCode());
            assertTrue(exception.getReason() != null && exception.getReason().contains("downstream error"));
            verify(cookieService).extractUserFromCookie(exchange);
            verify(webClient).post();
        }
    }
}



