package com.skillshub.gateway_service.config;

import com.skillshub.gateway_service.auth.service.SessionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomOAuth2SuccessHandlerTest {

    private static final String CLIENT_REGISTRATION_ID = "keycloak";
    private static final String PRINCIPAL_NAME = "test-user";
    private static final String ACCESS_TOKEN_VALUE = "access-token-value";
    private static final String REFRESH_TOKEN_VALUE = "refresh-token-value";

    @Mock
    private SessionService sessionService;

    @Mock
    private ReactiveOAuth2AuthorizedClientService authorizedClientService;

    @Mock
    private OAuth2AuthenticationToken oAuth2AuthenticationToken;

    @Mock
    private WebFilterChain webFilterChain;

    private CustomOAuth2SuccessHandler handler;

    private MockServerWebExchange exchange;
    private WebFilterExchange webFilterExchange;

    @BeforeEach
    void setUp() {
        handler = new CustomOAuth2SuccessHandler(sessionService, authorizedClientService);

        MockServerHttpRequest request = MockServerHttpRequest.get("/login/oauth2/code/keycloak").build();
        exchange = MockServerWebExchange.from(request);
        webFilterExchange = new WebFilterExchange(exchange, webFilterChain);
    }

    @Nested
    @DisplayName("onAuthenticationSuccess()")
    class OnAuthenticationSuccessTests {

        @Test
        @DisplayName("should call sessionService.handleLoginSuccess with access and refresh tokens when both are present")
        void onAuthenticationSuccess_withAccessAndRefreshTokens_shouldCallHandleLoginSuccess() {
            // Given
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    ACCESS_TOKEN_VALUE,
                    Instant.now(),
                    Instant.now().plusSeconds(3600)
            );

            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    REFRESH_TOKEN_VALUE,
                    Instant.now(),
                    Instant.now().plusSeconds(86400)
            );

            ClientRegistration clientRegistration = createClientRegistration();
            OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                    clientRegistration,
                    PRINCIPAL_NAME,
                    accessToken,
                    refreshToken
            );

            when(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()).thenReturn(CLIENT_REGISTRATION_ID);
            when(oAuth2AuthenticationToken.getName()).thenReturn(PRINCIPAL_NAME);
            when(authorizedClientService.loadAuthorizedClient(CLIENT_REGISTRATION_ID, PRINCIPAL_NAME))
                    .thenReturn(Mono.just(authorizedClient));
            when(sessionService.handleLoginSuccess(eq(ACCESS_TOKEN_VALUE), eq(REFRESH_TOKEN_VALUE), any(ServerWebExchange.class)))
                    .thenReturn(Mono.empty());

            // When
            handler.onAuthenticationSuccess(webFilterExchange, oAuth2AuthenticationToken).block();

            // Then
            verify(sessionService, times(1)).handleLoginSuccess(
                    eq(ACCESS_TOKEN_VALUE),
                    eq(REFRESH_TOKEN_VALUE),
                    any(ServerWebExchange.class)
            );
        }

        @Test
        @DisplayName("should call sessionService.handleLoginSuccess with refreshToken=null when refresh token is not present")
        void onAuthenticationSuccess_withAccessTokenOnly_shouldCallHandleLoginSuccessWithNullRefresh() {
            // Given
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    ACCESS_TOKEN_VALUE,
                    Instant.now(),
                    Instant.now().plusSeconds(3600)
            );

            ClientRegistration clientRegistration = createClientRegistration();
            OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                    clientRegistration,
                    PRINCIPAL_NAME,
                    accessToken,
                    null // No refresh token
            );

            when(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()).thenReturn(CLIENT_REGISTRATION_ID);
            when(oAuth2AuthenticationToken.getName()).thenReturn(PRINCIPAL_NAME);
            when(authorizedClientService.loadAuthorizedClient(CLIENT_REGISTRATION_ID, PRINCIPAL_NAME))
                    .thenReturn(Mono.just(authorizedClient));
            when(sessionService.handleLoginSuccess(eq(ACCESS_TOKEN_VALUE), isNull(), any(ServerWebExchange.class)))
                    .thenReturn(Mono.empty());

            // When
            handler.onAuthenticationSuccess(webFilterExchange, oAuth2AuthenticationToken).block();

            // Then
            verify(sessionService, times(1)).handleLoginSuccess(
                    eq(ACCESS_TOKEN_VALUE),
                    isNull(),
                    any(ServerWebExchange.class)
            );
        }

        @Test
        @DisplayName("should complete response without calling sessionService when authorized client is null")
        void onAuthenticationSuccess_withNullAuthorizedClient_shouldNotCallSessionService() {
            // Given
            when(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()).thenReturn(CLIENT_REGISTRATION_ID);
            when(oAuth2AuthenticationToken.getName()).thenReturn(PRINCIPAL_NAME);
            when(authorizedClientService.loadAuthorizedClient(CLIENT_REGISTRATION_ID, PRINCIPAL_NAME))
                    .thenReturn(Mono.empty());

            // When
            handler.onAuthenticationSuccess(webFilterExchange, oAuth2AuthenticationToken).block();

            // Then
            verify(sessionService, never()).handleLoginSuccess(any(), any(), any());
        }

        @Test
        @DisplayName("should complete response without calling sessionService when access token is null")
        void onAuthenticationSuccess_withNullAccessToken_shouldNotCallSessionService() {
            // Given
            OAuth2AuthorizedClient authorizedClient = mock(OAuth2AuthorizedClient.class);
            when(authorizedClient.getAccessToken()).thenReturn(null);

            when(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()).thenReturn(CLIENT_REGISTRATION_ID);
            when(oAuth2AuthenticationToken.getName()).thenReturn(PRINCIPAL_NAME);
            when(authorizedClientService.loadAuthorizedClient(CLIENT_REGISTRATION_ID, PRINCIPAL_NAME))
                    .thenReturn(Mono.just(authorizedClient));

            // When
            handler.onAuthenticationSuccess(webFilterExchange, oAuth2AuthenticationToken).block();

            // Then
            verify(sessionService, never()).handleLoginSuccess(any(), any(), any());
        }

        @Test
        @DisplayName("should complete response without calling sessionService when authentication is not OAuth2AuthenticationToken")
        void onAuthenticationSuccess_withNonOAuth2Authentication_shouldNotCallSessionService() {
            // Given
            Authentication nonOAuth2Auth = mock(Authentication.class);

            // When
            handler.onAuthenticationSuccess(webFilterExchange, nonOAuth2Auth).block();

            // Then
            verify(sessionService, never()).handleLoginSuccess(any(), any(), any());
            verify(authorizedClientService, never()).loadAuthorizedClient(any(), any());
        }
    }

    private ClientRegistration createClientRegistration() {
        return ClientRegistration.withRegistrationId(CLIENT_REGISTRATION_ID)
                .clientId("test-client-id")
                .clientSecret("test-client-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("http://localhost:8080/auth/realms/test/protocol/openid-connect/auth")
                .tokenUri("http://localhost:8080/auth/realms/test/protocol/openid-connect/token")
                .userInfoUri("http://localhost:8080/auth/realms/test/protocol/openid-connect/userinfo")
                .userNameAttributeName("sub")
                .build();
    }
}
