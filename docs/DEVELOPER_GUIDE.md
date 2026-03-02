# Developer Guide - Gateway Service

## Table of Contents

- [Key Concepts](#key-concepts)
- [Filter Architecture](#filter-architecture)
- [Authentication Management](#authentication-management)
- [Security: Header Spoofing](#security-header-spoofing)
- [Development Recipes](#development-recipes)
- [Known Issues](#known-issues)

---

## Key Concepts

### Spring Cloud Gateway in Reactive Mode

The Gateway uses **Spring WebFlux** (non-blocking) instead of servlet (blocking). This means:

- **All calls use `Mono<T>` and `Flux<T>`**
  ```java
  // ❌ WRONG: Using blocking code
  String token = service.getToken();  // ← Blocks the thread!

  // ✅ CORRECT: Using reactive types
  Mono<String> token = service.getTokenAsync();
  token.flatMap(t -> /* ... */);
  ```

- **Chain with `flatMap`, `map`, `switchIfEmpty`**
  ```java
  authService.getUser(token)
      .flatMap(user -> validateUser(user))
      .map(user -> new ResponseDto(user))
      .switchIfEmpty(Mono.error(new UnauthorizedException()))
      .onErrorResume(e -> handleError(e));
  ```

- **No `@Async`: use `Mono`/`Flux` directly**
  ```java
  // In a Spring Cloud Gateway service
  @Service
  public class MyService {
      // ✅ Return Mono/Flux, not Future/CompletableFuture
      public Mono<UserDto> getUser(String id) {
          return webClient.get()
              .uri("/users/{id}", id)
              .retrieve()
              .bodyToMono(UserDto.class);
      }
  }
  ```

### GlobalFilter vs GatewayFilter

| Aspect | GlobalFilter | GatewayFilter |
|--------|--------------|---------------|
| Scope | All routes | Specific routes |
| Implementation | `GlobalFilter` interface | `GatewayFilter` interface |
| Registration | Auto-detected (@Component) | Declared in route config |
| Order | `@Order(n)` | Via `filters:` in YAML |
| Usage | Global logic (auth, headers) | Route-specific logic |

**GlobalFilter example**:

```java
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class MyGlobalFilter implements GlobalFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Applies to ALL routes (unless bypassed)
        return chain.filter(exchange)
            .doOnSuccess(v -> log.info("Request processed"));
    }
}
```

**GatewayFilter example**:

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: my-route
          uri: http://backend
          predicates:
            - Path=/api/**
          filters:
            - MyCustomFilter  # ← Applies ONLY to this route
```

---

## Filter Architecture

The Gateway uses an **ordered filter chain**:

```
Incoming request
    ↓
[1] AuthCookieWebFilter       (@Order(HIGHEST_PRECEDENCE + 1))
    ├─ Extracts JWT from cookie
    ├─ Validates signature
    ├─ Handles refresh if expired
    └─ Injects Authentication → ReactiveSecurityContextHolder
    ↓
[2] XUserHeadersFilter         (@Order(HIGHEST_PRECEDENCE + 50))
    ├─ Reads Authentication from SecurityContext
    ├─ Extracts userId, email, roles
    ├─ Adds X-User-* headers
    └─ Prevents header spoofing (removes client-supplied headers)
    ↓
[3] Custom Gateway Filters     (defined per route)
    └─ StripPrefix, AddHeader, etc.
    ↓
[4] Route Handler (Backend)
    └─ X-User-* headers are now in the request
    ↓
Response back to client
```

### Ordering Gateway Filters

To add a filter to the chain:

```java
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 100)  // After others
public class MyFilter implements GlobalFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // IMPORTANT: always call chain.filter() to continue
        return chain.filter(exchange);
    }
}
```

---

## Authentication Management

### Complete Login/Token/Refresh Flow

```
1. Client → GET /api/auth/login
   ↓
   Gateway (SecurityConfig.oauth2Login())
   ├─ Generates state and code_verifier
   ├─ Redirects to Keycloak /auth?client_id=...&state=...&code_challenge=...
   └─ 302 Redirect

2. Client → Login on Keycloak
   (Keycloak: credentials verification, scope consent)
   └─ 302 Redirect to /login/oauth2/code/keycloak?code=XYZ&state=ABC

3. Gateway (automatic OAuth2LoginAuthenticationFilter)
   ├─ Validates the state
   ├─ Exchanges code → tokens with Keycloak
   │  POST /token
   │  ├─ grant_type=authorization_code
   │  ├─ code=XYZ
   │  ├─ client_id=gateway-service
   │  └─ redirect_uri=...
   │
   │  Keycloak response:
   │  {
   │    "access_token": "JWT...",
   │    "refresh_token": "JWT...",
   │    "expires_in": 1800,
   │    "token_type": "Bearer"
   │  }
   │
   ├─ Creates an OAuth2AuthenticationToken
   └─ Calls successHandler

4. CustomOAuth2SuccessHandler
   ├─ Reads accessToken and refreshToken
   ├─ SessionService.handleLoginSuccess()
   │  ├─ CookieService.createAuthCookie(accessToken)
   │  │  → ResponseCookie.from("SKILLSHUB_AUTH", token)
   │  │     .httpOnly(true).secure(COOKIE_SECURE).path("/")
   │  │     .sameSite(COOKIE_SAME_SITE).maxAge(1800)
   │  │     .build()
   │  │  → exchange.getResponse().addCookie()
   │  │
   │  ├─ createRefreshTokenCookie(refreshToken)
   │  │  → ResponseCookie.from("SKILLSHUB_AUTH_RT", refreshToken)
   │  │     ...same flags as access token
   │  │  → exchange.getResponse().addCookie()
   │  │
   │  └─ Redirect to AUTH_REDIRECT_AFTER_LOGIN
   │     (e.g. http://localhost:5173/)

5. Client → GET /api/users/me (with cookies)
   Header sent by browser:
   ├─ Cookie: SKILLSHUB_AUTH=JWT; SKILLSHUB_AUTH_RT=JWT

6. Gateway (AuthCookieWebFilter)
   ├─ exchange.getRequest().getCookies().getFirst("SKILLSHUB_AUTH")
   ├─ JwtDecoderService.decodeJwt(accessToken)
   │
   ├─ ✅ JWT valid AND not expired
   │  ├─ Extracts claims: sub (userId), email, roles
   │  ├─ Creates a JwtAuthenticationToken
   │  └─ ReactiveSecurityContextHolder.setContext(context)
   │
   ├─ ❌ JWT invalid (malformed, bad signature, etc.)
   │  ├─ Logs: "Invalid JWT cookie (not expired). Will clear cookies and return 401."
   │  ├─ clearCookiesAndUnauthorized()
   │  │  ├─ exchange.getResponse().addCookie(clearAuthCookie())
   │  │  │  → ResponseCookie.from("SKILLSHUB_AUTH", "").maxAge(0)...
   │  │  │
   │  │  ├─ exchange.getResponse().addCookie(clearRefreshTokenCookie())
   │  │  │  → ResponseCookie.from("SKILLSHUB_AUTH_RT", "").maxAge(0)...
   │  │  │
   │  │  └─ exchange.getResponse().setStatusCode(401)
   │  └─ return Mono.empty()
   │
   └─ ⏰ JWT expired (claims.exp < now)
      ├─ isExpiredJwt(exception) → true
      │
      ├─ refreshToken = exchange.getRequest().getCookies().getFirst("SKILLSHUB_AUTH_RT")
      │
      ├─ ❌ refreshToken empty/missing
      │  ├─ Logs: "Access token expired and no refresh token found -> 401"
      │  ├─ clearCookiesAndUnauthorized()
      │  └─ return Mono.empty()
      │
      └─ ✅ refreshToken present
         ├─ AuthCookieWebFilter.refreshAccessToken(refreshToken)
         │  └─ POST /realms/skillshub/protocol/openid-connect/token
         │     ├─ grant_type=refresh_token
         │     ├─ refresh_token=JWT
         │     └─ client_id=gateway-service
         │
         ├─ Keycloak responds
         │  ├─ HTTP 200 + {access_token, refresh_token, expires_in}
         │  ├─ HTTP 400 (refresh token expired or invalid)
         │  └─ HTTP 401 (client unauthorized)
         │
         ├─ ✅ HTTP 200 OK
         │  ├─ newAccessToken = response.getBody().getAccessToken()
         │  │
         │  ├─ ❌ newAccessToken empty
         │  │  ├─ clearCookiesAndUnauthorized()
         │  │  └─ return Mono.empty()
         │  │
         │  └─ ✅ newAccessToken not empty
         │     ├─ CookieService.createAuthCookie(newAccessToken)
         │     │  └─ exchange.getResponse().addCookie()
         │     │
         │     ├─ createRefreshTokenCookie(newRefreshToken)  // if present
         │     │  └─ exchange.getResponse().addCookie()
         │     │
         │     ├─ JwtDecoderService.decodeJwt(newAccessToken)
         │     │
         │     ├─ ✅ New token valid
         │     │  ├─ Logs: "Refresh success (cookies rewritten)"
         │     │  ├─ Injects Authentication
         │     │  └─ chain.filter(exchange)
         │     │
         │     └─ ❌ New token invalid
         │        ├─ clearCookiesAndUnauthorized()
         │        └─ return Mono.empty()
         │
         └─ ❌ HTTP 400/401 (refresh failed)
            ├─ Logs: "Refresh failed -> forcing re-login"
            ├─ clearCookiesAndUnauthorized()
            └─ return Mono.empty()

7. XUserHeadersFilter
   ├─ ReactiveSecurityContextHolder.getContext()
   │  → Reads the Authentication injected by AuthCookieWebFilter
   │
   ├─ isPublicApi("/api/users/me") → false
   │  └─ Filter continues
   │
   ├─ authentication.getPrincipal() → JWT claims
   ├─ authentication.getAuthorities() → ROLE_*
   │
   ├─ Extracts:
   │  ├─ userId = claims.get("sub")
   │  ├─ email = claims.get("email")
   │  └─ roles = authorities.stream().map(...).collect(...)
   │
   ├─ Mutate request headers
   │  ├─ h.remove("X-User-Id")
   │  ├─ h.set("X-User-Id", userId)
   │  ├─ h.remove("X-User-Email")
   │  ├─ h.set("X-User-Email", email)
   │  ├─ h.remove("X-User-Roles")
   │  └─ h.set("X-User-Roles", "STUDENT,TUTOR")
   │
   └─ exchange.mutate().request(...).build() → chain.filter()

8. Backend receives the request
   Headers:
   ├─ X-User-Id: 550e8400-e29b-41d4-a716-446655440000
   ├─ X-User-Email: john@example.com
   ├─ X-User-Roles: STUDENT,TUTOR
   └─ ... other standard headers
```

### Where Are Token Lifetimes Defined?

| Token | TTL | Where? | Configurable? |
|-------|-----|--------|---|
| **Access Token** | 30 min (default) | Keycloak realm settings | Yes (Keycloak Admin Console or API) |
| **Refresh Token** | 7 days (default) | Keycloak realm settings | Yes (Keycloak Admin Console or API) |
| **Access Cookie** | 30 min (default) | `COOKIE_MAX_AGE` env | Yes (env var) |
| **Refresh Cookie** | 7 days (default) | `REFRESH_COOKIE_MAX_AGE` env | Yes (env var) |

**Note**: Cookies and JWT tokens are **not synchronized**. For example:
- Cookie TTL = 30 min
- JWT TTL = 1 hour

After 30 min:
- The cookie is deleted by the browser
- But the JWT remains valid for another 30 min

The filter cannot access a JWT that no longer exists in the cookie → 401.

---

## Security: Header Spoofing

### Problem

Before the fix, the Gateway did:

```java
String existingUserId = exchange.getRequest().getHeaders().getFirst("X-User-Id");
if (!isBlank(existingUserId)) {
    // ⚠️ DANGER: Trusted client-supplied headers
    return chain.filter(exchange);  // Forward as-is
}
```

**Attack**:

```bash
# Malicious client forges a header
curl -H "X-User-Id: 550e8400-e29b-41d4-a716-446655440000" \
     -H "X-User-Email: admin@example.com" \
     https://skillshub.io/api/courses/search

# Gateway forwards the request with forged headers
# Backend loads admin's courses → data exposed ❌
```

### Implemented Solution

```java
@Override
public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    String path = exchange.getRequest().getURI().getPath();

    // PUBLIC routes: bypass
    if (isPublicApi(path)) {
        return chain.filter(exchange);
    }

    // PROTECTED routes: require SecurityContext
    return ReactiveSecurityContextHolder.getContext()
        .flatMap(ctx -> {
            // ✅ TRUSTED SOURCE: Extract from authenticated context
            Authentication auth = ctx.getAuthentication();
            String userId = asString(auth.getPrincipal()); // JWT claim 'sub'
            Object emailObj = auth.getDetails(); // JWT claim 'email'
            Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();

            // 🔒 CLEAR client-supplied headers
            ServerHttpRequest mutated = exchange.getRequest()
                .mutate()
                .headers(h -> {
                    h.remove(HEADER_USER_ID);      // Remove spoofed headers
                    h.remove(HEADER_USER_EMAIL);
                    h.remove(HEADER_USER_ROLES);

                    // ✅ SET ONLY trusted values
                    h.set(HEADER_USER_ID, userId);
                    h.set(HEADER_USER_EMAIL, email);
                    h.set(HEADER_USER_ROLES, roles);
                })
                .build();

            return chain.filter(exchange.mutate().request(mutated).build());
        })
        .switchIfEmpty(/* 401 */);
}
```

**Benefits**:

1. **Ignore client headers** → Immune to spoofing
2. **Validate the source** → JWT signed by Keycloak (trusted)
3. **Explicit is better** → Clear code showing security intent

---

## Development Recipes

### Add a New Authentication Endpoint

#### 1. Add a method to the controller

```java
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthMeService authMeService;

    @GetMapping("/profile")  // ← New endpoint
    public Mono<ResponseEntity<UserProfileDto>> getProfile() {
        return authMeService.getUserProfile()
            .map(profile -> ResponseEntity.ok(profile))
            .onErrorResume(e -> Mono.just(ResponseEntity.status(401).build()));
    }
}
```

#### 2. Update SecurityConfig to expose it

```java
@Bean
public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    return http
        .authorizeExchange(auth -> auth
            .pathMatchers("/api/auth/login").permitAll()
            .pathMatchers("/api/auth/logout").permitAll()
            .pathMatchers("/api/auth/me").permitAll()
            .pathMatchers("/api/auth/profile").permitAll()  // ← Add here
            .anyExchange().permitAll()
        )
        .build();
}
```

#### 3. Test

```bash
curl -v http://localhost:8080/api/auth/profile
# Should return 200 (public endpoint)
```

### Add a New Protected Route

#### 1. Declare the route in application.yml

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: new-protected-route
          uri: ${BACKEND_URI:http://localhost:10020}
          order: 100
          predicates:
            - Path=/api/new-feature/**
          filters:
            - StripPrefix=2  # Remove /api/new-feature
```

#### 2. Security is automatic

- `AuthCookieWebFilter` validates the JWT
- `XUserHeadersFilter` adds `X-User-*` headers
- Malicious requests without JWT → 401

#### 3. Test without authentication

```bash
curl -v http://localhost:8080/api/new-feature/data
# Expected: 401 Unauthorized (no cookie)
```

#### 4. Test with authentication

```bash
# 1. Login
curl -c cookies.txt -b cookies.txt http://localhost:8080/api/auth/login

# 2. Protected call
curl -b cookies.txt http://localhost:8080/api/new-feature/data
# Expected: 200 OK (with X-User-* headers)
```

### Debug a JWT Problem

#### 1. Check JWT content

```bash
# Extract the cookie
curl -v http://localhost:8080/api/auth/me 2>&1 | grep SKILLSHUB_AUTH

# Paste on https://jwt.io to decode (without verifying signature)
# Check claims:
# - sub (userId)
# - email
# - realm_access.roles
# - exp (expiration Unix timestamp)
```

#### 2. Check validation at Gateway startup

```bash
# Look at JWK signature logs
mvn spring-boot:run 2>&1 | grep -i "jwk\|rsa\|key"

# Verify the Gateway can fetch the public key
curl http://localhost:8085/realms/skillshub/protocol/openid-connect/certs
# Should return JSON with keys
```

#### 3. Add debug logs

In `AuthCookieWebFilter`:

```java
private Mono<Void> continueAuthenticated(ServerWebExchange exchange,
                                         GatewayFilterChain chain,
                                         Map<String, Object> claims) {
    log.info("✅ Valid JWT. Claims: sub={}, email={}",
             claims.get("sub"), claims.get("email"));

    // ...
}
```

Then:

```bash
mvn spring-boot:run 2>&1 | grep "Valid JWT"
```

### Test the Refresh Token

#### Scenario

1. Login and obtain cookies
2. Wait 30 min (or reduce `COOKIE_MAX_AGE` in dev)
3. Make an API call

#### Test Code

```java
@Test
void testRefreshTokenFlow() {
    // 1. Login
    var response = client.post()
        .uri("/api/auth/login")
        .exchange()
        .expectStatus().is3xxRedirection()
        .returnResult(Void.class);

    var cookies = response.getResponseHeaders().get("Set-Cookie");
    assertThat(cookies).hasSize(2); // SKILLSHUB_AUTH and SKILLSHUB_AUTH_RT

    // 2. Verify the new cookie is received after refresh
    // (simulate expiration by patching JWT time)

    var meResponse = client.get()
        .uri("/api/auth/me")
        .cookies(c -> c.addAll(/* parsed cookies */))
        .exchange()
        .expectStatus().isOk()
        .returnResult(UserDto.class);

    assertThat(meResponse.getResponseBody()).isNotNull();
}
```

---

## Known Issues

### 1. Double Set-Cookie (the February 2026 issue)

**Symptom**:

```
Set-Cookie: SKILLSHUB_AUTH=<token>; Max-Age=1800; ...
Set-Cookie: SKILLSHUB_AUTH=; Max-Age=0; ...
```

**Cause**: The filter both:
- Creates a new cookie (via `addCookie()`)
- Clears the old cookie (via `addCookie()` with `Max-Age=0`)

In the same response → Browser receives both → The clear wins.

**Solution**:

```java
// Verify that refreshAccessToken() does not call clearAuthCookie()
// if the refresh is OK

public Mono<Void> filter(...) {
    return decodeJwt(token)
        .then(chain.filter(exchange))  // ✅ Continue normally
        .onErrorResume(e -> {
            if (isExpiredJwt(e)) {
                return refreshAccessToken(refreshToken)
                    .flatMap(newToken -> {
                        // ✅ Create ONLY the new cookie
                        // ❌ Do NOT clear the old one
                        cookieService.createAuthCookie(newToken);
                        return chain.filter(exchange);
                    });
            }
            // ❌ Other errors → clear + 401
            return clearCookiesAndUnauthorized(exchange);
        });
}
```

### 2. CORS Preflight Requests

**Symptom**: `OPTIONS /api/...` returns 403 or 401

**Cause**: Preflight requests do not contain the JWT

**Solution**: Add `OPTIONS` to the whitelist in SecurityConfig

```java
.authorizeExchange(auth -> auth
    .pathMatchers(HttpMethod.OPTIONS).permitAll()  // ← Add
    .pathMatchers("/api/auth/**").permitAll()
    .anyExchange().permitAll()
)
```

### 3. "localhost" vs "127.0.0.1"

**Problem**: Cookies are not sent if domain mismatches

```
Gateway:     http://localhost:8080
Browser:     http://127.0.0.1:8080
Cookie:      Domain=localhost
Result:      Cookie NOT SENT (different domain) ❌
```

**Solution**: Always use `localhost` (not `127.0.0.1`)

### 4. `SameSite=None` Without `Secure=true`

**Problem**: Browser rejects the cookie

```
Set-Cookie: SKILLSHUB_AUTH=...; SameSite=None; Secure=false
Result: Browser rejects (invalid combination) ❌
```

**Solution**: In local development, use `SameSite=Lax`:

```yaml
skillshub:
  auth:
    cookie-same-site: Lax  # Local dev
    cookie-secure: false   # Local dev (no HTTPS)
```

In production:

```yaml
skillshub:
  auth:
    cookie-same-site: None  # Production
    cookie-secure: true     # Production (HTTPS required)
```

---

## Code Reference

### Key Classes

| Class | File | Role |
|-------|------|------|
| `AuthCookieWebFilter` | `auth/filter/` | **Auth core** - Validates JWT, handles refresh |
| `CookieService` | `auth/service/` | Creates/clears cookies |
| `SessionService` | `auth/service/` | Login/logout business logic |
| `XUserHeadersFilter` | `auth/filter/` | Propagates identity (headers) |
| `AuthController` | `auth/controller/` | `/api/auth/**` endpoints |
| `SecurityConfig` | `config/` | Spring Security OAuth2 setup |
| `JwtDecoderService` | `auth/service/` | Validates and decodes JWT |

### Configurable Properties

See `src/main/resources/application.yml` and `AuthCookieProperties.java`.

Main properties:

```yaml
skillshub:
  auth:
    cookie-name: SKILLSHUB_AUTH           # Access cookie name
    cookie-domain: .duckdns.org           # Shared domain (prod)
    cookie-secure: true                   # HTTPS required (prod)
    cookie-same-site: None                # Cross-site (prod)
    cookie-max-age: 1800                  # 30 min
    redirect-after-login: https://...     # Where to redirect after login
    redirect-after-logout: https://...    # Where to redirect after logout

app:
  backend:
    base-url: http://backend-service:10020

  keycloak:
    base-url: https://keycloak.skillshub.io
    realm: skillshub
    admin:
      client-id: admin-cli
      client-secret: <secret>
```

---

**Last updated**: February 2026
**Author**: Gateway Team
