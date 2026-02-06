package com.skillshub.gateway_service.auth.filter;



import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.skillshub.gateway_service.auth.AuthCookieProperties;
import com.skillshub.gateway_service.auth.service.CookieService;
import com.skillshub.gateway_service.auth.service.JwtDecoderService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;


import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthCookieWebFilterTest {

    private static final String COOKIE_NAME = "SKILLSHUB_AUTH";
    private static final String REFRESH_COOKIE_NAME = "SKILLSHUB_AUTH_RT";

    @Mock
    private JwtDecoderService jwtDecoderService;

    @Mock
    private CookieService cookieService;

    @Mock
    private AuthCookieProperties props;

    @Mock
    private WebFilterChain chain;

    @Mock
    private WebClient.Builder webClientBuilder;

    private AuthCookieWebFilter filter;

    @BeforeEach
    void setUp() {
        filter = new AuthCookieWebFilter(jwtDecoderService, cookieService, props, webClientBuilder);
    }

    @Nested
    @DisplayName("filter()")
    class FilterTests {

        @Test
        @DisplayName("should call chain.filter and leave response status unset when no access cookie is present")
        void filter_withNoAccessCookie_shouldCallChainFilter() {
            // Given
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/some-endpoint").build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            when(props.getCookieName()).thenReturn(COOKIE_NAME);
            when(chain.filter(exchange)).thenReturn(Mono.empty());

            // When
            filter.filter(exchange, chain).block();

            // Then
            verify(chain, times(1)).filter(exchange);
            assertThat(exchange.getResponse().getStatusCode()).isNull();
        }

        @Test
        @DisplayName("should call chain.filter and leave response status unset when access cookie is blank")
        void filter_withBlankAccessCookie_shouldCallChainFilter() {
            // Given
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/some-endpoint")
                    .cookie(new HttpCookie(COOKIE_NAME, "   "))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            when(props.getCookieName()).thenReturn(COOKIE_NAME);
            when(chain.filter(exchange)).thenReturn(Mono.empty());

            // When
            filter.filter(exchange, chain).block();

            // Then
            verify(chain, times(1)).filter(exchange);
            assertThat(exchange.getResponse().getStatusCode()).isNull();
        }

        @Test
        @DisplayName("should call chain.filter when access token is valid")
        void filter_withValidAccessToken_shouldCallChainFilter() {
            // Given
            String validToken = "valid-access-token";
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/some-endpoint")
                    .cookie(new HttpCookie(COOKIE_NAME, validToken))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            Map<String, Object> claims = Map.of(
                    "sub", "user-123",
                    "preferred_username", "testuser"
            );

            when(props.getCookieName()).thenReturn(COOKIE_NAME);
            when(jwtDecoderService.decodeJwt(validToken)).thenReturn(claims);
            when(chain.filter(any())).thenReturn(Mono.empty());

            // When
            filter.filter(exchange, chain).block();

            // Then
            verify(jwtDecoderService, times(1)).decodeJwt(validToken);
            verify(chain, times(1)).filter(exchange);
        }

        @Test
        @DisplayName("should return 401 and clear cookies when JWT is invalid (non-expired)")
        void filter_withInvalidNonExpiredToken_shouldReturn401AndClearCookies() {
            // Given
            String invalidToken = "invalid-token";
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/some-endpoint")
                    .cookie(new HttpCookie(COOKIE_NAME, invalidToken))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            ResponseCookie clearAccessCookie = ResponseCookie.from(COOKIE_NAME, "")
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(0)
                    .build();

            when(props.getCookieName()).thenReturn(COOKIE_NAME);
            when(props.isCookieSecure()).thenReturn(true);
            when(props.getCookieSameSite()).thenReturn("Lax");
            when(props.getCookieDomain()).thenReturn(null);
            when(jwtDecoderService.decodeJwt(invalidToken)).thenThrow(new RuntimeException("bad token"));
            when(cookieService.clearAuthCookie()).thenReturn(clearAccessCookie);

            // When
            filter.filter(exchange, chain).block();

            // Then
            verify(jwtDecoderService, times(1)).decodeJwt(invalidToken);
            verify(cookieService, times(1)).clearAuthCookie();
            verify(chain, never()).filter(any());

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(exchange.getResponse().getCookies()).containsKey(COOKIE_NAME);
            assertThat(exchange.getResponse().getCookies()).containsKey(REFRESH_COOKIE_NAME);
        }

        @Test
        @DisplayName("should bypass filter for /api/auth/login path")
        void filter_withAuthLoginPath_shouldBypassFilter() {
            // Given
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/auth/login").build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            when(chain.filter(exchange)).thenReturn(Mono.empty());

            // When
            filter.filter(exchange, chain).block();

            // Then
            verify(chain, times(1)).filter(exchange);
            verify(props, never()).getCookieName();
            verify(jwtDecoderService, never()).decodeJwt(any());
        }

        @Test
        @DisplayName("should bypass filter for /api/auth/logout path")
        void filter_withAuthLogoutPath_shouldBypassFilter() {
            // Given
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/auth/logout").build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            when(chain.filter(exchange)).thenReturn(Mono.empty());

            // When
            filter.filter(exchange, chain).block();

            // Then
            verify(chain, times(1)).filter(exchange);
            verify(props, never()).getCookieName();
            verify(jwtDecoderService, never()).decodeJwt(any());
        }

        @Test
        @DisplayName("should bypass filter for /actuator/** paths")
        void filter_withActuatorPath_shouldBypassFilter() {
            // Given
            MockServerHttpRequest request = MockServerHttpRequest.get("/actuator/health").build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            when(chain.filter(exchange)).thenReturn(Mono.empty());

            // When
            filter.filter(exchange, chain).block();

            // Then
            verify(chain, times(1)).filter(exchange);
            verify(props, never()).getCookieName();
            verify(jwtDecoderService, never()).decodeJwt(any());
        }

        @Test
        @DisplayName("should continue with empty roles when realm_access is not a Map (extractRoles error branch)")
        void filter_withInvalidRealmAccessFormat_shouldContinueWithEmptyRoles() {
            // Given
            String validToken = "validAT";
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/some-endpoint")
                    .cookie(new HttpCookie(COOKIE_NAME, validToken))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            // Claims where "realm_access" is a String instead of a Map
            Map<String, Object> claims = Map.of(
                    "sub", "user-123",
                    "preferred_username", "testuser",
                    "realm_access", "invalid-string-value"
            );

            when(props.getCookieName()).thenReturn(COOKIE_NAME);
            when(jwtDecoderService.decodeJwt(validToken)).thenReturn(claims);
            when(chain.filter(any())).thenReturn(Mono.empty());

            // When
            filter.filter(exchange, chain).block();

            // Then
            // Verify chain.filter was called (request continues authenticated with empty roles)
            verify(jwtDecoderService, times(1)).decodeJwt(validToken);
            verify(chain, times(1)).filter(exchange);

            // Filter should not throw and should not return 401
            assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("should continue with empty roles when realm_access.roles is not a List (extractRoles error branch)")
        void filter_withInvalidRolesFormat_shouldContinueWithEmptyRoles() {
            // Given
            String validToken = "validAT";
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/some-endpoint")
                    .cookie(new HttpCookie(COOKIE_NAME, validToken))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            // Claims where "realm_access.roles" is a String instead of a List
            Map<String, Object> claims = Map.of(
                    "sub", "user-123",
                    "preferred_username", "testuser",
                    "realm_access", Map.of("roles", "not-a-list")
            );

            when(props.getCookieName()).thenReturn(COOKIE_NAME);
            when(jwtDecoderService.decodeJwt(validToken)).thenReturn(claims);
            when(chain.filter(any())).thenReturn(Mono.empty());

            // When
            filter.filter(exchange, chain).block();

            // Then
            // Verify chain.filter was called (request continues authenticated with empty roles)
            verify(jwtDecoderService, times(1)).decodeJwt(validToken);
            verify(chain, times(1)).filter(exchange);

            // Filter should not throw and should not return 401
            assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("should return 401 and clear cookies when JWT is expired and no refresh cookie is present")
        void filter_withExpiredTokenAndNoRefreshCookie_shouldReturn401AndClearCookies() {
            // Given
            String expiredToken = "expiredAT";
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/some-endpoint")
                    .cookie(new HttpCookie(COOKIE_NAME, expiredToken))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            ResponseCookie clearAccessCookie = ResponseCookie.from(COOKIE_NAME, "")
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(0)
                    .build();

            when(props.getCookieName()).thenReturn(COOKIE_NAME);
            when(props.isCookieSecure()).thenReturn(true);
            when(props.getCookieSameSite()).thenReturn("Lax");
            when(props.getCookieDomain()).thenReturn(null);
            when(jwtDecoderService.decodeJwt(expiredToken)).thenThrow(new RuntimeException("Expired JWT token"));
            when(cookieService.clearAuthCookie()).thenReturn(clearAccessCookie);

            // When
            filter.filter(exchange, chain).block();

            // Then
            verify(jwtDecoderService, times(1)).decodeJwt(expiredToken);
            verify(cookieService, times(1)).clearAuthCookie();
            verify(chain, never()).filter(any());

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(exchange.getResponse().getCookies()).containsKey(COOKIE_NAME);
            assertThat(exchange.getResponse().getCookies()).containsKey(REFRESH_COOKIE_NAME);

            // Verify refresh cookie is cleared with Max-Age=0
            ResponseCookie refreshCookie = exchange.getResponse().getCookies().getFirst(REFRESH_COOKIE_NAME);
            assertThat(refreshCookie).isNotNull();
            assertThat(refreshCookie.getMaxAge().getSeconds()).isEqualTo(0);
            assertThat(refreshCookie.getValue()).isEmpty();
        }
    }

    @Nested
    @DisplayName("filter() with WireMock - refresh token flow")
    class FilterWithWireMockTests {

        private WireMockServer wireMockServer;

        @Mock
        private JwtDecoderService jwtDecoderServiceMock;

        @Mock
        private CookieService cookieServiceMock;

        @Mock
        private AuthCookieProperties propsMock;

        @Mock
        private WebFilterChain chainMock;

        private AuthCookieWebFilter filterWithWireMock;

        @BeforeEach
        void setUp() {
            wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
            wireMockServer.start();

            WebClient.Builder realWebClientBuilder = WebClient.builder();
            filterWithWireMock = new AuthCookieWebFilter(jwtDecoderServiceMock, cookieServiceMock, propsMock, realWebClientBuilder);

            // Configure keycloak token URI and client ID using reflection
            String tokenUri = "http://localhost:" + wireMockServer.port() + "/token";
            ReflectionTestUtils.setField(filterWithWireMock, "keycloakTokenUri", tokenUri);
            ReflectionTestUtils.setField(filterWithWireMock, "keycloakClientId", "gateway-service");
        }

        @AfterEach
        void tearDown() {
            if (wireMockServer != null && wireMockServer.isRunning()) {
                wireMockServer.stop();
            }
        }

        @Test
        @DisplayName("should refresh token and continue when access token is expired but refresh token is valid")
        void filter_withExpiredTokenAndValidRefreshToken_shouldRefreshAndContinue() {
            // Given - Stub WireMock to return new tokens
            wireMockServer.stubFor(post(urlEqualTo("/token"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody("{\"access_token\":\"newAT\",\"refresh_token\":\"newRT\"}")));

            // Request with expired access token and refresh token
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/some-endpoint")
                    .cookie(new HttpCookie(COOKIE_NAME, "expiredAT"))
                    .cookie(new HttpCookie(REFRESH_COOKIE_NAME, "rt1"))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            // Mock props
            when(propsMock.getCookieName()).thenReturn(COOKIE_NAME);
            when(propsMock.isCookieSecure()).thenReturn(true);
            when(propsMock.getCookieSameSite()).thenReturn("None");
            when(propsMock.getCookieDomain()).thenReturn("");

            // Mock JWT decoder - first call throws expired, second call returns claims
            when(jwtDecoderServiceMock.decodeJwt("expiredAT"))
                    .thenThrow(new RuntimeException("Expired JWT token"));
            Map<String, Object> claims = Map.of(
                    "sub", "user-123",
                    "realm_access", Map.of("roles", List.of("TUTOR"))
            );
            when(jwtDecoderServiceMock.decodeJwt("newAT")).thenReturn(claims);

            // Mock cookie service to return new access cookie
            ResponseCookie newAccessCookie = ResponseCookie.from(COOKIE_NAME, "newAT")
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .sameSite("None")
                    .maxAge(3600)
                    .build();
            when(cookieServiceMock.createAuthCookie("newAT")).thenReturn(newAccessCookie);

            // Mock chain to return empty
            when(chainMock.filter(any())).thenReturn(Mono.empty());

            // When
            filterWithWireMock.filter(exchange, chainMock).block();

            // Then
            // Verify chain.filter was called (request continues)
            verify(chainMock, times(1)).filter(exchange);

            // Verify response status is not 401
            assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.UNAUTHORIZED);

            // Verify response has Set-Cookie for SKILLSHUB_AUTH (new access token)
            assertThat(exchange.getResponse().getCookies()).containsKey(COOKIE_NAME);
            ResponseCookie accessCookieResult = exchange.getResponse().getCookies().getFirst(COOKIE_NAME);
            assertThat(accessCookieResult).isNotNull();
            assertThat(accessCookieResult.getValue()).isEqualTo("newAT");

            // Verify response has Set-Cookie for SKILLSHUB_AUTH_RT (new refresh token)
            assertThat(exchange.getResponse().getCookies()).containsKey(REFRESH_COOKIE_NAME);
            ResponseCookie refreshCookieResult = exchange.getResponse().getCookies().getFirst(REFRESH_COOKIE_NAME);
            assertThat(refreshCookieResult).isNotNull();
            assertThat(refreshCookieResult.getValue()).isEqualTo("newRT");

            // Verify WireMock was called
            wireMockServer.verify(postRequestedFor(urlEqualTo("/token")));
        }

        @Test
        @DisplayName("should return 401 and clear cookies when refresh token response has no access_token")
        void filter_withExpiredTokenAndRefreshResponseMissingAccessToken_shouldReturn401AndClearCookies() {
            // Given - Stub WireMock to return response without access_token
            wireMockServer.stubFor(post(urlEqualTo("/token"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody("{\"refresh_token\":\"newRT\"}")));

            // Request with expired access token and refresh token
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/some-endpoint")
                    .cookie(new HttpCookie(COOKIE_NAME, "expiredAT"))
                    .cookie(new HttpCookie(REFRESH_COOKIE_NAME, "rt1"))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            // Mock props
            when(propsMock.getCookieName()).thenReturn(COOKIE_NAME);
            when(propsMock.isCookieSecure()).thenReturn(true);
            when(propsMock.getCookieSameSite()).thenReturn("None");
            when(propsMock.getCookieDomain()).thenReturn("");

            // Mock JWT decoder - throws expired for the initial token
            when(jwtDecoderServiceMock.decodeJwt("expiredAT"))
                    .thenThrow(new RuntimeException("Expired JWT token"));

            // Mock cookie service to return clear cookie
            ResponseCookie clearAccessCookie = ResponseCookie.from(COOKIE_NAME, "")
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(0)
                    .build();
            when(cookieServiceMock.clearAuthCookie()).thenReturn(clearAccessCookie);

            // When
            filterWithWireMock.filter(exchange, chainMock).block();

            // Then
            // Verify cookieService.clearAuthCookie() was called
            verify(cookieServiceMock, times(1)).clearAuthCookie();

            // Verify chain.filter was NOT called
            verify(chainMock, never()).filter(any());

            // Verify response status is 401
            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

            // Verify response has cleared access cookie
            assertThat(exchange.getResponse().getCookies()).containsKey(COOKIE_NAME);

            // Verify response has cleared refresh cookie with Max-Age=0
            assertThat(exchange.getResponse().getCookies()).containsKey(REFRESH_COOKIE_NAME);
            ResponseCookie refreshCookieResult = exchange.getResponse().getCookies().getFirst(REFRESH_COOKIE_NAME);
            assertThat(refreshCookieResult).isNotNull();
            assertThat(refreshCookieResult.getValue()).isEmpty();
            assertThat(refreshCookieResult.getMaxAge().getSeconds()).isEqualTo(0);

            // Verify WireMock was called
            wireMockServer.verify(postRequestedFor(urlEqualTo("/token")));
        }

        @Test
        @DisplayName("should return 401 and clear cookies when refresh token endpoint returns 400 Bad Request")
        void filter_withExpiredTokenAndRefreshEndpointReturns400_shouldReturn401AndClearCookies() {
            // Given - Stub WireMock to return 400 Bad Request
            wireMockServer.stubFor(post(urlEqualTo("/token"))
                    .willReturn(aResponse()
                            .withStatus(400)
                            .withHeader("Content-Type", "application/json")
                            .withBody("{\"error\":\"invalid_grant\",\"error_description\":\"Token is not active\"}")));

            // Request with expired access token and refresh token
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/some-endpoint")
                    .cookie(new HttpCookie(COOKIE_NAME, "expiredAT"))
                    .cookie(new HttpCookie(REFRESH_COOKIE_NAME, "rt1"))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            // Mock props
            when(propsMock.getCookieName()).thenReturn(COOKIE_NAME);
            when(propsMock.isCookieSecure()).thenReturn(true);
            when(propsMock.getCookieSameSite()).thenReturn("None");
            when(propsMock.getCookieDomain()).thenReturn("");

            // Mock JWT decoder - throws expired for the initial token
            when(jwtDecoderServiceMock.decodeJwt("expiredAT"))
                    .thenThrow(new RuntimeException("Expired JWT token"));

            // Mock cookie service to return clear cookie
            ResponseCookie clearAccessCookie = ResponseCookie.from(COOKIE_NAME, "")
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(0)
                    .build();
            when(cookieServiceMock.clearAuthCookie()).thenReturn(clearAccessCookie);

            // When
            filterWithWireMock.filter(exchange, chainMock).block();

            // Then
            // Verify cookieService.clearAuthCookie() was called
            verify(cookieServiceMock, times(1)).clearAuthCookie();

            // Verify chain.filter was NOT called
            verify(chainMock, never()).filter(any());

            // Verify response status is 401
            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

            // Verify response has cleared access cookie
            assertThat(exchange.getResponse().getCookies()).containsKey(COOKIE_NAME);

            // Verify response has cleared refresh cookie with Max-Age=0
            assertThat(exchange.getResponse().getCookies()).containsKey(REFRESH_COOKIE_NAME);
            ResponseCookie refreshCookieResult = exchange.getResponse().getCookies().getFirst(REFRESH_COOKIE_NAME);
            assertThat(refreshCookieResult).isNotNull();
            assertThat(refreshCookieResult.getValue()).isEmpty();
            assertThat(refreshCookieResult.getMaxAge().getSeconds()).isEqualTo(0);

            // Verify WireMock was called
            wireMockServer.verify(postRequestedFor(urlEqualTo("/token")));
        }

        @Test
        @DisplayName("should return 401 and clear cookies when refresh token endpoint returns 401 Unauthorized")
        void filter_withExpiredTokenAndRefreshEndpointReturns401_shouldReturn401AndClearCookies() {
            // Given - Stub WireMock to return 401 Unauthorized
            wireMockServer.stubFor(post(urlEqualTo("/token"))
                    .willReturn(aResponse()
                            .withStatus(401)
                            .withHeader("Content-Type", "application/json")
                            .withBody("{\"error\":\"unauthorized\",\"error_description\":\"Invalid client credentials\"}")));

            // Request with expired access token and refresh token
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/some-endpoint")
                    .cookie(new HttpCookie(COOKIE_NAME, "expiredAT"))
                    .cookie(new HttpCookie(REFRESH_COOKIE_NAME, "rt1"))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            // Mock props
            when(propsMock.getCookieName()).thenReturn(COOKIE_NAME);
            when(propsMock.isCookieSecure()).thenReturn(true);
            when(propsMock.getCookieSameSite()).thenReturn("None");
            when(propsMock.getCookieDomain()).thenReturn("");

            // Mock JWT decoder - throws expired for the initial token
            when(jwtDecoderServiceMock.decodeJwt("expiredAT"))
                    .thenThrow(new RuntimeException("Expired JWT token"));

            // Mock cookie service to return clear cookie
            ResponseCookie clearAccessCookie = ResponseCookie.from(COOKIE_NAME, "")
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(0)
                    .build();
            when(cookieServiceMock.clearAuthCookie()).thenReturn(clearAccessCookie);

            // When
            filterWithWireMock.filter(exchange, chainMock).block();

            // Then
            // Verify cookieService.clearAuthCookie() was called
            verify(cookieServiceMock, times(1)).clearAuthCookie();

            // Verify chain.filter was NOT called
            verify(chainMock, never()).filter(any());

            // Verify response status is 401
            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

            // Verify response has cleared access cookie
            assertThat(exchange.getResponse().getCookies()).containsKey(COOKIE_NAME);

            // Verify response has cleared refresh cookie with Max-Age=0
            assertThat(exchange.getResponse().getCookies()).containsKey(REFRESH_COOKIE_NAME);
            ResponseCookie refreshCookieResult = exchange.getResponse().getCookies().getFirst(REFRESH_COOKIE_NAME);
            assertThat(refreshCookieResult).isNotNull();
            assertThat(refreshCookieResult.getValue()).isEmpty();
            assertThat(refreshCookieResult.getMaxAge().getSeconds()).isEqualTo(0);

            // Verify WireMock was called
            wireMockServer.verify(postRequestedFor(urlEqualTo("/token")));
        }

        @Test
        @DisplayName("should set Domain on refresh cookie when cookieDomain is non-blank")
        void filter_withRefreshSuccessAndNonBlankDomain_shouldSetDomainOnCookies() {
            // Given - Stub WireMock to return new tokens
            wireMockServer.stubFor(post(urlEqualTo("/token"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody("{\"access_token\":\"newAT\",\"refresh_token\":\"newRT\"}")));

            // Request with expired access token and refresh token
            MockServerHttpRequest request = MockServerHttpRequest.get("/api/some-endpoint")
                    .cookie(new HttpCookie(COOKIE_NAME, "expiredAT"))
                    .cookie(new HttpCookie(REFRESH_COOKIE_NAME, "rt1"))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            // Mock props - with non-blank domain
            when(propsMock.getCookieName()).thenReturn(COOKIE_NAME);
            when(propsMock.isCookieSecure()).thenReturn(true);
            when(propsMock.getCookieSameSite()).thenReturn("None");
            when(propsMock.getCookieDomain()).thenReturn("example.com");

            // Mock JWT decoder - first call throws expired, second call returns claims
            when(jwtDecoderServiceMock.decodeJwt("expiredAT"))
                    .thenThrow(new RuntimeException("Expired JWT token"));
            Map<String, Object> claims = Map.of(
                    "sub", "user-123",
                    "realm_access", Map.of("roles", List.of("TUTOR"))
            );
            when(jwtDecoderServiceMock.decodeJwt("newAT")).thenReturn(claims);

            // Mock cookie service to return new access cookie with domain
            ResponseCookie newAccessCookie = ResponseCookie.from(COOKIE_NAME, "newAT")
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .sameSite("None")
                    .domain("example.com")
                    .maxAge(3600)
                    .build();
            when(cookieServiceMock.createAuthCookie("newAT")).thenReturn(newAccessCookie);

            // Mock chain to return empty
            when(chainMock.filter(any())).thenReturn(Mono.empty());

            // When
            filterWithWireMock.filter(exchange, chainMock).block();

            // Then
            // Verify chain.filter was called (request continues)
            verify(chainMock, times(1)).filter(exchange);

            // Verify response status is not 401
            assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.UNAUTHORIZED);

            // Verify response has Set-Cookie for SKILLSHUB_AUTH_RT with Domain=example.com
            assertThat(exchange.getResponse().getCookies()).containsKey(REFRESH_COOKIE_NAME);
            ResponseCookie refreshCookieResult = exchange.getResponse().getCookies().getFirst(REFRESH_COOKIE_NAME);
            assertThat(refreshCookieResult).isNotNull();
            assertThat(refreshCookieResult.getValue()).isEqualTo("newRT");
            assertThat(refreshCookieResult.getDomain()).isEqualTo("example.com");

            // Also verify using toString() that Domain is present in the cookie header
            String cookieString = refreshCookieResult.toString();
            assertThat(cookieString).contains("Domain=example.com");

            // Verify WireMock was called
            wireMockServer.verify(postRequestedFor(urlEqualTo("/token")));
        }
    }
}
