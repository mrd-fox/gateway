package com.skillshub.gateway_service.auth.service;

import com.skillshub.gateway_service.auth.AuthCookieProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseCookie;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class CookieServiceTest {

    private static final String COOKIE_NAME = "SKILLSHUB_AUTH";
    private static final boolean COOKIE_SECURE = true;
    private static final String COOKIE_SAME_SITE = "None";
    private static final String COOKIE_DOMAIN_EMPTY = "";
    private static final long COOKIE_MAX_AGE = 86400L;

    @Mock
    private JwtDecoderService jwtDecoderService;

    private AuthCookieProperties props;

    private CookieService cookieService;

    @BeforeEach
    void setUp() {
        // Create a real AuthCookieProperties object with stubbed values
        props = new AuthCookieProperties();
        props.setCookieName(COOKIE_NAME);
        props.setCookieSecure(COOKIE_SECURE);
        props.setCookieSameSite(COOKIE_SAME_SITE);
        props.setCookieDomain(COOKIE_DOMAIN_EMPTY);
        props.setCookieMaxAge(COOKIE_MAX_AGE);

        cookieService = new CookieService(props, jwtDecoderService);
    }

    @Nested
    @DisplayName("createAuthCookie()")
    class CreateAuthCookieTests {

        @Test
        @DisplayName("should create cookie with correct name")
        void createAuthCookie_shouldHaveCorrectName() {
            // When
            ResponseCookie cookie = cookieService.createAuthCookie("token");

            // Then
            assertThat(cookie.getName()).isEqualTo(COOKIE_NAME);
        }

        @Test
        @DisplayName("should create cookie with correct value")
        void createAuthCookie_shouldHaveCorrectValue() {
            // When
            ResponseCookie cookie = cookieService.createAuthCookie("token");

            // Then
            assertThat(cookie.getValue()).isEqualTo("token");
        }

        @Test
        @DisplayName("should create cookie with httpOnly=true")
        void createAuthCookie_shouldBeHttpOnly() {
            // When
            ResponseCookie cookie = cookieService.createAuthCookie("token");

            // Then
            assertThat(cookie.isHttpOnly()).isTrue();
        }

        @Test
        @DisplayName("should create cookie with secure=true")
        void createAuthCookie_shouldBeSecure() {
            // When
            ResponseCookie cookie = cookieService.createAuthCookie("token");

            // Then
            assertThat(cookie.isSecure()).isTrue();
        }

        @Test
        @DisplayName("should create cookie with path=/")
        void createAuthCookie_shouldHaveRootPath() {
            // When
            ResponseCookie cookie = cookieService.createAuthCookie("token");

            // Then
            assertThat(cookie.getPath()).isEqualTo("/");
        }

        @Test
        @DisplayName("should create cookie with maxAge=86400 seconds")
        void createAuthCookie_shouldHaveCorrectMaxAge() {
            // When
            ResponseCookie cookie = cookieService.createAuthCookie("token");

            // Then
            assertThat(cookie.getMaxAge()).isEqualTo(Duration.ofSeconds(86400));
        }

        @Test
        @DisplayName("should create cookie with sameSite=None")
        void createAuthCookie_shouldHaveCorrectSameSite() {
            // When
            ResponseCookie cookie = cookieService.createAuthCookie("token");

            // Then
            assertThat(cookie.getSameSite()).isEqualTo("None");
        }

        @Test
        @DisplayName("should NOT set domain when cookieDomain is empty")
        void createAuthCookie_shouldNotSetDomainWhenEmpty() {
            // When
            ResponseCookie cookie = cookieService.createAuthCookie("token");

            // Then
            assertThat(cookie.getDomain()).isNull();
        }

        @Test
        @DisplayName("should NOT set domain when cookieDomain is blank")
        void createAuthCookie_shouldNotSetDomainWhenBlank() {
            // Given
            props.setCookieDomain("   ");

            // When
            ResponseCookie cookie = cookieService.createAuthCookie("token");

            // Then
            assertThat(cookie.getDomain()).isNull();
        }

        @Test
        @DisplayName("should set domain when cookieDomain is configured")
        void createAuthCookie_shouldSetDomainWhenConfigured() {
            // Given
            props.setCookieDomain(".skillshub.com");

            // When
            ResponseCookie cookie = cookieService.createAuthCookie("token");

            // Then
            assertThat(cookie.getDomain()).isEqualTo(".skillshub.com");
        }

        @Test
        @DisplayName("should create cookie with all expected attributes")
        void createAuthCookie_shouldHaveAllExpectedAttributes() {
            // When
            ResponseCookie cookie = cookieService.createAuthCookie("my-access-token");

            // Then
            assertThat(cookie.getName()).isEqualTo(COOKIE_NAME);
            assertThat(cookie.getValue()).isEqualTo("my-access-token");
            assertThat(cookie.isHttpOnly()).isTrue();
            assertThat(cookie.isSecure()).isTrue();
            assertThat(cookie.getPath()).isEqualTo("/");
            assertThat(cookie.getMaxAge()).isEqualTo(Duration.ofSeconds(86400));
            assertThat(cookie.getSameSite()).isEqualTo("None");
            assertThat(cookie.getDomain()).isNull();
        }
    }

    @Nested
    @DisplayName("clearAuthCookie()")
    class ClearAuthCookieTests {

        @Test
        @DisplayName("should create clear cookie with correct name")
        void clearAuthCookie_shouldHaveCorrectName() {
            // When
            ResponseCookie cookie = cookieService.clearAuthCookie();

            // Then
            assertThat(cookie.getName()).isEqualTo(COOKIE_NAME);
        }

        @Test
        @DisplayName("should create clear cookie with empty value")
        void clearAuthCookie_shouldHaveEmptyValue() {
            // When
            ResponseCookie cookie = cookieService.clearAuthCookie();

            // Then
            assertThat(cookie.getValue()).isEmpty();
        }

        @Test
        @DisplayName("should create clear cookie with maxAge=0 (Duration.ZERO)")
        void clearAuthCookie_shouldHaveZeroMaxAge() {
            // When
            ResponseCookie cookie = cookieService.clearAuthCookie();

            // Then
            assertThat(cookie.getMaxAge()).isEqualTo(Duration.ZERO);
        }

        @Test
        @DisplayName("should create clear cookie with httpOnly=true")
        void clearAuthCookie_shouldBeHttpOnly() {
            // When
            ResponseCookie cookie = cookieService.clearAuthCookie();

            // Then
            assertThat(cookie.isHttpOnly()).isTrue();
        }

        @Test
        @DisplayName("should create clear cookie with secure=true")
        void clearAuthCookie_shouldBeSecure() {
            // When
            ResponseCookie cookie = cookieService.clearAuthCookie();

            // Then
            assertThat(cookie.isSecure()).isTrue();
        }

        @Test
        @DisplayName("should create clear cookie with path=/")
        void clearAuthCookie_shouldHaveRootPath() {
            // When
            ResponseCookie cookie = cookieService.clearAuthCookie();

            // Then
            assertThat(cookie.getPath()).isEqualTo("/");
        }

        @Test
        @DisplayName("should create clear cookie with sameSite=None")
        void clearAuthCookie_shouldHaveCorrectSameSite() {
            // When
            ResponseCookie cookie = cookieService.clearAuthCookie();

            // Then
            assertThat(cookie.getSameSite()).isEqualTo("None");
        }

        @Test
        @DisplayName("should NOT set domain when cookieDomain is empty")
        void clearAuthCookie_shouldNotSetDomainWhenEmpty() {
            // When
            ResponseCookie cookie = cookieService.clearAuthCookie();

            // Then
            assertThat(cookie.getDomain()).isNull();
        }

        @Test
        @DisplayName("should set domain when cookieDomain is configured")
        void clearAuthCookie_shouldSetDomainWhenConfigured() {
            // Given
            props.setCookieDomain(".skillshub.com");

            // When
            ResponseCookie cookie = cookieService.clearAuthCookie();

            // Then
            assertThat(cookie.getDomain()).isEqualTo(".skillshub.com");
        }

        @Test
        @DisplayName("should create clear cookie with all expected attributes")
        void clearAuthCookie_shouldHaveAllExpectedAttributes() {
            // When
            ResponseCookie cookie = cookieService.clearAuthCookie();

            // Then
            assertThat(cookie.getName()).isEqualTo(COOKIE_NAME);
            assertThat(cookie.getValue()).isEmpty();
            assertThat(cookie.getMaxAge()).isEqualTo(Duration.ZERO);
            assertThat(cookie.isHttpOnly()).isTrue();
            assertThat(cookie.isSecure()).isTrue();
            assertThat(cookie.getPath()).isEqualTo("/");
            assertThat(cookie.getSameSite()).isEqualTo("None");
            assertThat(cookie.getDomain()).isNull();
        }
    }
}
