package com.skillshub.gateway_service.auth.filter;

import com.skillshub.gateway_service.auth.AuthCookieProperties;
import com.skillshub.gateway_service.auth.service.CookieService;
import com.skillshub.gateway_service.auth.service.JwtDecoderService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Map;

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
    }
}
