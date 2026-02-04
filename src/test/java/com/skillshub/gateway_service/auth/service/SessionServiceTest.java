package com.skillshub.gateway_service.auth.service;

import com.skillshub.gateway_service.auth.AuthCookieProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SessionServiceTest {

    private static final String COOKIE_NAME = "SKILLSHUB_AUTH";
    private static final String REFRESH_COOKIE_NAME = "SKILLSHUB_AUTH_RT";

    private static final String REDIRECT_AFTER_LOGIN = "http://localhost:3000/dashboard";
    private static final String REDIRECT_AFTER_LOGOUT = "http://localhost:3000/";

    private static final String KEYCLOAK_BASE_URL = "http://auth.skillshub.local:8085";
    private static final String REALM = "skillshub";

    @Mock
    private CookieService cookieService;

    @Mock
    private AuthCookieProperties props;

    private SessionService sessionService;

    private MockServerWebExchange exchange;

    @BeforeEach
    void setUp() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/auth/login").build();
        exchange = MockServerWebExchange.from(request);

        sessionService = new SessionService(cookieService, props, KEYCLOAK_BASE_URL, REALM);
    }

    @Nested
    @DisplayName("performLogin()")
    class PerformLoginTests {

        @Test
        @DisplayName("should redirect to OAuth2 authorization endpoint with status 302 FOUND")
        void performLogin_shouldRedirectToKeycloak() {
            sessionService.performLogin(exchange).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
            assertThat(exchange.getResponse().getHeaders().getLocation())
                    .isEqualTo(URI.create("/oauth2/authorization/keycloak"));
        }
    }

    @Nested
    @DisplayName("handleLoginSuccess()")
    class HandleLoginSuccessTests {

        @Test
        @DisplayName("should return 401 UNAUTHORIZED when accessToken is null")
        void handleLoginSuccess_withNullAccessToken_shouldReturn401() {
            sessionService.handleLoginSuccess(null, "refresh-token", exchange).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("should return 401 UNAUTHORIZED when accessToken is blank")
        void handleLoginSuccess_withBlankAccessToken_shouldReturn401() {
            sessionService.handleLoginSuccess("   ", "refresh-token", exchange).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("should return 401 UNAUTHORIZED when accessToken is empty")
        void handleLoginSuccess_withEmptyAccessToken_shouldReturn401() {
            sessionService.handleLoginSuccess("", "refresh-token", exchange).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        @Test
        @DisplayName("should set only access cookie and redirect when refreshToken is null")
        void handleLoginSuccess_withNullRefreshToken_shouldSetOnlyAccessCookie() {
            String accessToken = "valid-access-token";
            ResponseCookie accessCookie = ResponseCookie.from(COOKIE_NAME, accessToken)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(3600)
                    .build();

            when(cookieService.createAuthCookie(accessToken)).thenReturn(accessCookie);
            when(props.getRedirectAfterLogin()).thenReturn(REDIRECT_AFTER_LOGIN);

            sessionService.handleLoginSuccess(accessToken, null, exchange).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
            assertThat(exchange.getResponse().getHeaders().getLocation())
                    .isEqualTo(URI.create(REDIRECT_AFTER_LOGIN));

            assertThat(exchange.getResponse().getCookies()).containsKey(COOKIE_NAME);
            assertThat(exchange.getResponse().getCookies()).doesNotContainKey(REFRESH_COOKIE_NAME);

            ResponseCookie accessCookieResult = exchange.getResponse().getCookies().getFirst(COOKIE_NAME);
            assertThat(accessCookieResult).isNotNull();
            assertThat(accessCookieResult.getMaxAge().getSeconds()).isEqualTo(3600);

            verify(cookieService).createAuthCookie(accessToken);
        }

        @Test
        @DisplayName("should set only access cookie and redirect when refreshToken is blank")
        void handleLoginSuccess_withBlankRefreshToken_shouldSetOnlyAccessCookie() {
            String accessToken = "valid-access-token";
            ResponseCookie accessCookie = ResponseCookie.from(COOKIE_NAME, accessToken)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(3600)
                    .build();

            when(cookieService.createAuthCookie(accessToken)).thenReturn(accessCookie);
            when(props.getRedirectAfterLogin()).thenReturn(REDIRECT_AFTER_LOGIN);

            sessionService.handleLoginSuccess(accessToken, "   ", exchange).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
            assertThat(exchange.getResponse().getHeaders().getLocation())
                    .isEqualTo(URI.create(REDIRECT_AFTER_LOGIN));

            assertThat(exchange.getResponse().getCookies()).containsKey(COOKIE_NAME);
            assertThat(exchange.getResponse().getCookies()).doesNotContainKey(REFRESH_COOKIE_NAME);

            verify(cookieService).createAuthCookie(accessToken);
        }

        @Test
        @DisplayName("should set access cookie and refresh cookie when both tokens are present")
        void handleLoginSuccess_withBothTokens_shouldSetBothCookies() {
            String accessToken = "valid-access-token";
            String refreshToken = "valid-refresh-token";

            ResponseCookie accessCookie = ResponseCookie.from(COOKIE_NAME, accessToken)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(3600)
                    .build();

            when(cookieService.createAuthCookie(accessToken)).thenReturn(accessCookie);
            when(props.getRedirectAfterLogin()).thenReturn(REDIRECT_AFTER_LOGIN);
            when(props.getCookieName()).thenReturn(COOKIE_NAME);
            when(props.isCookieSecure()).thenReturn(true);
            when(props.getCookieSameSite()).thenReturn("Lax");
            when(props.getCookieDomain()).thenReturn(null);

            sessionService.handleLoginSuccess(accessToken, refreshToken, exchange).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
            assertThat(exchange.getResponse().getHeaders().getLocation())
                    .isEqualTo(URI.create(REDIRECT_AFTER_LOGIN));

            assertThat(exchange.getResponse().getCookies()).containsKey(COOKIE_NAME);
            assertThat(exchange.getResponse().getCookies()).containsKey(REFRESH_COOKIE_NAME);

            ResponseCookie refreshCookie = exchange.getResponse().getCookies().getFirst(REFRESH_COOKIE_NAME);
            assertThat(refreshCookie).isNotNull();
            assertThat(refreshCookie.getMaxAge().toDays()).isEqualTo(7);
            assertThat(refreshCookie.isHttpOnly()).isTrue();
            assertThat(refreshCookie.isSecure()).isTrue();
            assertThat(refreshCookie.getPath()).isEqualTo("/");
            assertThat(refreshCookie.getSameSite()).isEqualTo("Lax");

            verify(cookieService).createAuthCookie(accessToken);
        }

        @Test
        @DisplayName("should set domain on refresh cookie when configured")
        void handleLoginSuccess_withCookieDomain_shouldSetDomainOnRefreshCookie() {
            String accessToken = "valid-access-token";
            String refreshToken = "valid-refresh-token";
            String cookieDomain = ".skillshub.com";

            ResponseCookie accessCookie = ResponseCookie.from(COOKIE_NAME, accessToken)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(3600)
                    .build();

            when(cookieService.createAuthCookie(accessToken)).thenReturn(accessCookie);
            when(props.getRedirectAfterLogin()).thenReturn(REDIRECT_AFTER_LOGIN);
            when(props.getCookieName()).thenReturn(COOKIE_NAME);
            when(props.isCookieSecure()).thenReturn(true);
            when(props.getCookieSameSite()).thenReturn("Strict");
            when(props.getCookieDomain()).thenReturn(cookieDomain);

            sessionService.handleLoginSuccess(accessToken, refreshToken, exchange).block();

            ResponseCookie refreshCookie = exchange.getResponse().getCookies().getFirst(REFRESH_COOKIE_NAME);
            assertThat(refreshCookie).isNotNull();
            assertThat(refreshCookie.getDomain()).isEqualTo(cookieDomain);
        }

        @Test
        @DisplayName("should return 500 INTERNAL_SERVER_ERROR when CookieService returns null")
        void handleLoginSuccess_whenCookieServiceReturnsNull_shouldReturn500() {
            String accessToken = "valid-access-token";
            when(cookieService.createAuthCookie(accessToken)).thenReturn(null);

            sessionService.handleLoginSuccess(accessToken, "refresh-token", exchange).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Nested
    @DisplayName("performLogout()")
    class PerformLogoutTests {

        @Test
        @DisplayName("should clear access+refresh cookies and redirect to frontend")
        void performLogout_shouldClearCookiesAndRedirectToFrontend() {
            ResponseCookie clearAccessCookie = ResponseCookie.from(COOKIE_NAME, "")
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(0)
                    .build();

            when(cookieService.clearAuthCookie()).thenReturn(clearAccessCookie);

            when(props.getRedirectAfterLogout()).thenReturn(REDIRECT_AFTER_LOGOUT);
            when(props.getCookieName()).thenReturn(COOKIE_NAME);
            when(props.isCookieSecure()).thenReturn(true);
            when(props.getCookieSameSite()).thenReturn("Lax");
            when(props.getCookieDomain()).thenReturn(null);

            sessionService.performLogout(exchange).block();

            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
            assertThat(exchange.getResponse().getHeaders().getLocation())
                    .isEqualTo(URI.create(REDIRECT_AFTER_LOGOUT));

            assertThat(exchange.getResponse().getCookies()).containsKey(COOKIE_NAME);
            assertThat(exchange.getResponse().getCookies()).containsKey(REFRESH_COOKIE_NAME);

            ResponseCookie accessCookie = exchange.getResponse().getCookies().getFirst(COOKIE_NAME);
            assertThat(accessCookie).isNotNull();
            assertThat(accessCookie.getMaxAge().getSeconds()).isEqualTo(0);

            ResponseCookie refreshCookie = exchange.getResponse().getCookies().getFirst(REFRESH_COOKIE_NAME);
            assertThat(refreshCookie).isNotNull();
            assertThat(refreshCookie.getMaxAge().getSeconds()).isEqualTo(0);
            assertThat(refreshCookie.getValue()).isEmpty();

            verify(cookieService).clearAuthCookie();
        }

        @Test
        @DisplayName("should set domain on clear refresh cookie when configured")
        void performLogout_withCookieDomain_shouldSetDomainOnClearRefreshCookie() {
            String cookieDomain = ".skillshub.com";

            ResponseCookie clearAccessCookie = ResponseCookie.from(COOKIE_NAME, "")
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(0)
                    .build();

            when(cookieService.clearAuthCookie()).thenReturn(clearAccessCookie);

            when(props.getRedirectAfterLogout()).thenReturn(REDIRECT_AFTER_LOGOUT);
            when(props.getCookieName()).thenReturn(COOKIE_NAME);
            when(props.isCookieSecure()).thenReturn(true);
            when(props.getCookieSameSite()).thenReturn("Strict");
            when(props.getCookieDomain()).thenReturn(cookieDomain);

            sessionService.performLogout(exchange).block();

            ResponseCookie refreshCookie = exchange.getResponse().getCookies().getFirst(REFRESH_COOKIE_NAME);
            assertThat(refreshCookie).isNotNull();
            assertThat(refreshCookie.getDomain()).isEqualTo(cookieDomain);
        }
    }
}