# Gateway Service - Skillshub API Gateway

## Table of Contents

- [Overview](#overview)
- [Technical Architecture](#technical-architecture)
- [Prerequisites](#prerequisites)
- [Installation and Configuration](#installation-and-configuration)
- [Starting the Service](#starting-the-service)
- [Developer Guide](#developer-guide)
- [Tests](#tests)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)

---

## Overview

The **Gateway Service** is a reactive API Gateway that is part of the Skillshub infrastructure. It acts as the single entry point for accessing backend services and handles:

- **Authentication and authorization** via Keycloak (OAuth2/OIDC)
- **Routing and load balancing** of API requests
- **Session management** and authentication cookies
- **Secure identity propagation** to backend services
- **CORS and security** at the gateway level

### Infrastructure Context

The Gateway is **one of 4 main components** of the Skillshub infrastructure:

```
┌─────────────────────────────────────────────────────────────┐
│                   Frontend (skillshub-UI)                    │
│                   Vue 3 + Vite + TypeScript                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ HTTPS (ports 8080/80)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Gateway Service (this project)                   │
│         Spring Cloud Gateway + WebFlux + OAuth2              │
│  ├─ OAuth2/OIDC Authentication (Keycloak)                    │
│  ├─ Session cookie management                                │
│  ├─ Secure identity propagation                              │
│  └─ Reactive routing to backend services                     │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
    ┌────────────┐  ┌────────────┐  ┌──────────────────┐
    │  Backend   │  │ Keycloak   │  │  Other services  │
    │  Service   │  │  (IdP)     │  │                  │
    │            │  │            │  │  - Notifications │
    │ - Users    │  │ - Realms   │  │  - Analytics     │
    │ - Courses  │  │ - Tokens   │  │  - etc.          │
    │ - Orders   │  │ - Themes   │  │                  │
    └────────────┘  └────────────┘  └──────────────────┘
```

---

## Technical Architecture

### Technology Stack

| Component | Version | Role |
|-----------|---------|------|
| **Java** | 21 | Runtime |
| **Spring Boot** | 3.3.4 | Reactive web framework |
| **Spring Cloud Gateway** | 2023.0.3 | Routing and filtering |
| **Spring Security** | 6.x | OAuth2/OIDC, authentication |
| **Spring WebFlux** | 3.3.4 | Reactive API (non-blocking) |
| **Keycloak** | 23.x | Identity Provider (IdP) |
| **Maven** | 3.9.9 | Dependency management and build |
| **Docker** | Latest | Containerization |
| **JaCoCo** | 0.8.12 | Test coverage |

### Internal Architecture

```
com.skillshub.gateway_service/
├── GatewayServiceApplication                 # Spring Boot entry point
│
├── config/                                    # Global configuration
│   ├── SecurityConfig                        # OAuth2 and WebFluxSecurity config
│   ├── CorsConfig                            # CORS configuration
│   ├── CustomOAuth2SuccessHandler            # Post-login success handler (cookies)
│   └── StartupLogger                         # Startup logger
│
├── auth/                                     # Authentication logic
│   ├── AuthCookieProperties                  # Cookie properties (YAML)
│   │
│   ├── controller/
│   │   └── AuthController                    # Endpoints: /api/auth/**
│   │       ├── GET  /api/auth/me             # Current user info
│   │       ├── POST /api/auth/login          # Initiates OAuth2 login flow
│   │       └── POST /api/auth/logout         # Logout (clears cookies)
│   │
│   ├── service/
│   │   ├── CookieService                     # Cookie creation/deletion
│   │   ├── SessionService                    # Session management (login/logout)
│   │   ├── AuthMeService                     # User info extraction
│   │   └── JwtDecoderService                 # JWT validation and decoding
│   │
│   └── filter/
│       └── AuthCookieWebFilter               # WebFlux filter for JWT validation
│           ├─ Validates the access cookie
│           ├─ Handles refresh token if expired
│           └─ Injects Authentication into ReactiveSecurityContextHolder
│
├── user/                                     # User management
│   ├── controller/
│   │   └── UserController                    # Local endpoints: /api/users/**
│   │
│   ├── service/
│   │   └── UserService                       # User business logic
│   │
│   ├── client/
│   │   └── BackendClient                     # HTTP client to backend
│   │
│   └── command/
│       └── UserCommand                       # User commands (CQRS)
│
└── filter/                                   # Global filters
    └── XUserHeadersFilter                    # Secure identity propagation
        ├─ Adds X-User-* headers
        ├─ Prevents header spoofing
        └─ Allows /api/public/** without auth
```

### Authentication Flow

```
1️⃣  LOGIN INITIATION
    Client → GET /api/auth/login
    ↓
    Gateway → 302 Redirect to Keycloak /auth?client_id=...
    ↓
    Client → Keycloak (credentials entry)

2️⃣  AUTHORIZATION CODE EXCHANGE
    Client ← 302 Redirect to /login/oauth2/code/keycloak?code=...&state=...
    ↓
    Gateway OAuth2LoginAuthenticationFilter
    ├─ Exchanges code → tokens with Keycloak
    ├─ Creates an OAuth2AuthenticationToken
    └─ Calls CustomOAuth2SuccessHandler

3️⃣  COOKIE CREATION (CustomOAuth2SuccessHandler)
    SessionService.handleLoginSuccess(tokens)
    ├─ Creates SKILLSHUB_AUTH (access_token, Max-Age=1800s)
    ├─ Creates SKILLSHUB_AUTH_RT (refresh_token)
    └─ Set-Cookie headers

4️⃣  SUBSEQUENT API CALLS
    Client → GET /api/users/me (with cookies SKILLSHUB_AUTH, SKILLSHUB_AUTH_RT)
    ↓
    AuthCookieWebFilter
    ├─ Extracts JWT from SKILLSHUB_AUTH cookie
    ├─ Validates JWT (signature, claims, expiration)
    │
    ├─ ✅ JWT valid and not expired
    │   └─ Injects Authentication into ReactiveSecurityContextHolder
    │       └─ Passes to route handler
    │
    ├─ ❌ JWT invalid (not expired)
    │   └─ Clear cookies + 401 Unauthorized
    │
    └─ ⏰ JWT expired
        ├─ Reads refresh token from SKILLSHUB_AUTH_RT cookie
        │
        ├─ Calls Keycloak token endpoint
        │   GET /realms/skillshub/protocol/openid-connect/token
        │       ?grant_type=refresh_token&refresh_token=...
        │
        ├─ ✅ Refresh OK
        │   ├─ Creates SKILLSHUB_AUTH (new access_token)
        │   ├─ Creates SKILLSHUB_AUTH_RT (new refresh_token if needed)
        │   └─ Validates new access token and injects Authentication
        │       └─ Passes to route handler
        │
        └─ ❌ Refresh fails
            └─ Clear cookies + 401 Unauthorized (forces re-login)

5️⃣  BACKEND PROPAGATION (XUserHeadersFilter)
    Gateway → Backend (/api/courses/search)
    ├─ Reads Authentication from ReactiveSecurityContextHolder
    ├─ Extracts userId, email, roles from JWT claims
    │
    ├─ /api/public/** : bypasses the filter
    │   └─ No authentication required
    │
    └─ /api/courses/** : protected route
        ├─ Adds secure headers
        │   ├─ X-User-Id: <uuid>
        │   ├─ X-User-Email: <email>
        │   └─ X-User-Roles: <comma-separated>
        │
        ├─ Backend validates entitlements based on X-User-Id
        └─ Returns to client
```

### Cookie Management

#### Access Cookie (`SKILLSHUB_AUTH`)

- **Content**: JWT access token signed by Keycloak
- **TTL**: 30 minutes (configured via `COOKIE_MAX_AGE=1800`)
- **Flags**:
  - `HttpOnly`: Prevents JavaScript access (XSS protection)
  - `Secure`: HTTPS-only transmission (except local dev)
  - `SameSite=None`: Allows cross-site requests (required for OAuth2 redirect)
  - `Domain=.duckdns.org`: Shared across subdomains (prod)
  - `Path=/`: Accessible across the entire domain

#### Refresh Cookie (`SKILLSHUB_AUTH_RT`)

- **Content**: JWT refresh token signed by Keycloak
- **TTL**: 7 days (configured in Keycloak)
- **Flags**: Same as the access cookie
- **Usage**: Used to renew the access token without re-login

### Security

#### Header Spoofing Prevention

The `XUserHeadersFilter` ensures that `X-User-*` headers cannot be forged by a malicious client:

```java
// Ignore headers sent by the client
h.remove(HEADER_USER_ID);
h.remove(HEADER_USER_EMAIL);
h.remove(HEADER_USER_ROLES);

// Add ONLY values from the Authentication object
h.set(HEADER_USER_ID, userId);
h.set(HEADER_USER_EMAIL, email);
h.set(HEADER_USER_ROLES, roles);
```

#### OAuth2/OIDC Authentication

- **Issuer**: Keycloak (configured via `KEYCLOAK_ISSUER_URI`)
- **Client**: `gateway-service`
- **Validation**: JWT signature via JWK Set (`KEYCLOAK_JWK_SET_URI`)
- **Scopes**: `openid`, `profile`, `email`

---

## Prerequisites

### Development Environment

- **Java 21** (JDK + JRE)
  ```bash
  java -version
  # openjdk version "21" 2023-09-19
  ```

- **Maven 3.9+**
  ```bash
  mvn --version
  # Apache Maven 3.9.9
  ```

- **Docker & Docker Compose** (for local deployment)
  ```bash
  docker --version
  docker-compose --version
  ```

- **Keycloak 23+** (running somewhere)
  - Realm: `skillshub`
  - Client: `gateway-service`

- **Backend Service** (running somewhere)
  - URL accessible via `BACKEND_URI`

### System Configuration

- **Port 8080** available (or configurable via `SERVER_PORT`)
- **Docker network** `skillshub-net` existing (for Docker)

---

## Installation and Configuration

### 1. Clone the Project

```bash
git clone <repository-url>
cd PROJECT/gateway
```

### 2. Environment Variables

#### Local Development Mode (non-Docker)

Create or edit `envs/dev/dev.env`:

```bash
# Spring Profile
SPRING_PROFILES_ACTIVE=dev

# Gateway
SERVER_ADDRESS=0.0.0.0
SERVER_PORT=8080

# Backend
BACKEND_URI=http://localhost:10020

# Keycloak (Docker on localhost:8085)
KEYCLOAK_ISSUER_URI=http://localhost:8085/realms/skillshub
KEYCLOAK_AUTHORIZATION_URI=http://localhost:8085/realms/skillshub/protocol/openid-connect/auth
KEYCLOAK_TOKEN_URI=http://localhost:8085/realms/skillshub/protocol/openid-connect/token
KEYCLOAK_JWK_SET_URI=http://localhost:8085/realms/skillshub/protocol/openid-connect/certs
KEYCLOAK_USER_INFO_URI=http://localhost:8085/realms/skillshub/protocol/openid-connect/userinfo

# Cookies (dev: no domain or HTTPS)
COOKIE_SECURE=false
COOKIE_SAME_SITE=Lax
COOKIE_MAX_AGE=1800

# Redirects
AUTH_REDIRECT_AFTER_LOGIN=http://localhost:5173/
AUTH_REDIRECT_AFTER_LOGOUT=http://localhost:5173/

# Keycloak Admin (for internal requests)
KEYCLOAK_BASE_URL=http://localhost:8085
KEYCLOAK_REALM=skillshub
KEYCLOAK_ADMIN_CLIENT_ID=admin-cli
KEYCLOAK_ADMIN_CLIENT_SECRET=<secret>
```

#### Docker Hybrid Mode (Gateway in Docker, local services)

Edit `envs/dev/docker-hybrid.env`:

```bash
SPRING_PROFILES_ACTIVE=docker-hybrid
SERVER_PORT=8080

# Backend accessible from container via host.docker.internal
BACKEND_URI=http://host.docker.internal:10020

# Keycloak also on host
KEYCLOAK_ISSUER_URI=http://host.docker.internal:8085/realms/skillshub
# ...other URLs using host.docker.internal
```

#### Production Mode

Edit `deploy/envs/prod.env`:

```bash
SPRING_PROFILES_ACTIVE=prod
SERVER_PORT=8080

# Backend
BACKEND_URI=http://backend-service:10020

# Keycloak
KEYCLOAK_ISSUER_URI=https://keycloak.skillshub.io/realms/skillshub
KEYCLOAK_AUTHORIZATION_URI=https://keycloak.skillshub.io/realms/skillshub/protocol/openid-connect/auth
# ...

# Cookies (prod: shared domain and HTTPS)
COOKIE_DOMAIN=.skillshub.io
COOKIE_SECURE=true
COOKIE_SAME_SITE=None

AUTH_REDIRECT_AFTER_LOGIN=https://skillshub.io/
AUTH_REDIRECT_AFTER_LOGOUT=https://skillshub.io/
```

### 3. Keycloak Configuration

The Gateway requires a Keycloak client `gateway-service` with:

- **Access Type**: Public
- **Valid Redirect URIs**:
  - `http://localhost:8080/login/oauth2/code/keycloak` (dev)
  - `https://skillshub.io/login/oauth2/code/keycloak` (prod)
- **Scopes**: `openid`, `profile`, `email` (enabled)

---

## Starting the Service

### Local Development Mode (Maven)

```bash
# Load environment variables
# Export them in your terminal before running

# Build and run
mvn spring-boot:run -Dspring-boot.run.arguments="--spring.config.additional-location=file:./envs/dev/dev.env"

# Or just build
mvn clean install

# Then run the JAR
java -jar target/gateway-service-1.0.0-SNAPSHOT.jar --spring.config.additional-location=file:envs/dev/dev.env
```

**Expected output**:

```
===============================================================

    🚀  Gateway Service Started
    Name:    gateway-service
    Version: 1.0.0-SNAPSHOT

    Base URL:    http://localhost:8080
    Routes URL:  http://localhost:8080/actuator/gateway/routes
    Health URL:  http://localhost:8080/actuator/health

===============================================================
```

### Docker Hybrid Mode

```bash
# Build the image
docker build -t gateway-service:latest .

# Start the container
docker-compose -f docker-compose.yml up --build

# Check status
docker ps | grep gateway-service
docker logs gateway-service
```

**With custom environment**:

```bash
docker-compose -f docker-compose.yml --env-file envs/dev/docker-hybrid.env up
```

### Production Mode

```bash
# Build and push the image
docker build -t ghcr.io/mrd-fox/gateway:latest .
docker push ghcr.io/mrd-fox/gateway:latest

# Deploy
docker-compose -f deploy/prod.docker-compose.yml up -d

# Verify
curl http://localhost:8080/actuator/health
```

---

## Developer Guide

### Key File Architecture

#### `src/main/java/com/skillshub/gateway_service/`

**Authentication and security**:

- `auth/AuthCookieProperties.java` → Mapped YAML configuration
- `auth/filter/AuthCookieWebFilter.java` → **Key component**: JWT validation and refresh token handling
- `auth/service/CookieService.java` → Cookie creation/deletion
- `auth/service/SessionService.java` → Login/logout management
- `config/SecurityConfig.java` → Spring Security configuration
- `config/CustomOAuth2SuccessHandler.java` → After successful OAuth2 login

**Endpoints and business logic**:

- `auth/controller/AuthController.java` → `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`
- `user/controller/UserController.java` → `/api/users/**` (local endpoints)
- `user/service/UserService.java` → User logic
- `user/client/BackendClient.java` → HTTP client to backend

**Global filters**:

- `auth/filter/XUserHeadersFilter.java` → **Security**: Injects `X-User-*` headers

#### Configuration

- `src/main/resources/application.yml` → Main Spring configuration
- `src/main/resources/application-prod.yml` → Production profile
- `envs/dev/dev.env` → Dev variables
- `envs/dev/docker-hybrid.env` → Docker hybrid variables
- `deploy/envs/prod.env` → Production variables

### Adding a New Route

#### 1. Route to Backend

In `application.yml`, under `spring.cloud.gateway.routes`:

```yaml
- id: courses
  uri: ${BACKEND_URI:http://localhost:10020}
  predicates:
    - Path=/api/courses/**
  filters:
    - StripPrefix=2  # Remove /api/courses
```

The route will be protected by `AuthCookieWebFilter` and enriched by `XUserHeadersFilter`.

#### 2. Local Endpoint

Create a controller:

```java
@RestController
@RequestMapping("/api/local-feature")
public class LocalFeatureController {

    @GetMapping
    public Mono<ResponseEntity<LocalFeatureDto>> get(ServerWebExchange exchange) {
        return SecurityContextHolder.getContext()
            .map(ctx -> ctx.getAuthentication())
            .map(auth -> /* ... */);
    }
}
```

#### 3. Public Route

Add to `SecurityConfig.authorizeExchange()`:

```java
.pathMatchers("/api/public/**").permitAll()
```

And in `XUserHeadersFilter.isPublicApi()`:

```java
private boolean isPublicApi(String path) {
    return path != null && (
        path.startsWith("/api/public/") ||
        path.startsWith("/api/docs/**")
    );
}
```

### Development Workflow

1. **Create a feature branch**
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Modify the code**
   - Implement in `src/main/java`
   - Add tests in `src/test/java`

3. **Test locally**
   ```bash
   mvn test
   mvn clean install
   java -jar target/gateway-service-1.0.0-SNAPSHOT.jar
   ```

4. **Check coverage**
   ```bash
   mvn clean test
   # Report generated: target/site/jacoco/index.html
   ```

5. **Commit and push**
   ```bash
   git add .
   git commit -m "feat: description"
   git push origin feature/my-feature
   ```

---

## Tests

### Running Tests

```bash
# All tests
mvn clean test

# A specific test
mvn test -Dtest=AuthCookieWebFilterTest

# Without integration tests
mvn test -P skip-it

# With coverage report
mvn clean test jacoco:report
# Report: target/site/jacoco/index.html
```

### Quality Analysis (Sonar)

```bash
# Analyze the project
mvn clean test -P sonar sonar:sonar \
  -Dsonar.projectKey=gateway-service \
  -Dsonar.organization=mrd-fox \
  -Dsonar.host.url=https://sonarcloud.io \
  -Dsonar.login=<token>

# Or via CI/CD (see `.gitlab-ci.yml`)
```

---

## Deployment

### Before Deploying

```bash
# 1. Verify tests pass
mvn clean test

# 2. Build the image
docker build -t ghcr.io/mrd-fox/gateway:latest .

# 3. Test locally
docker run -p 8080:8080 --env-file deploy/envs/prod.env ghcr.io/mrd-fox/gateway:latest

# 4. Check health
curl http://localhost:8080/actuator/health
```

### Production Deployment

**Via Docker Compose** (recommended):

```bash
# On the production server
ssh user@prod-server

cd /path/to/skillshub

# Pull the latest image
docker pull ghcr.io/mrd-fox/gateway:latest

# Start the compose
docker-compose -f gateway/deploy/prod.docker-compose.yml up -d

# Check logs
docker logs gateway-service
```

**Via Kubernetes** (if applicable):

```bash
kubectl set image deployment/gateway-service \
  gateway=ghcr.io/mrd-fox/gateway:latest \
  --record
```

### Verify Deployment

```bash
# Health check
curl https://skillshub.io/actuator/health

# Available routes
curl https://skillshub.io/actuator/gateway/routes

# Login test
curl -X POST https://skillshub.io/api/auth/login

# Check logs
docker logs -f gateway-service
```

---

## Troubleshooting

### Problem: `401 Unauthorized` on `/api/auth/me`

**Possible causes**:

1. **Expired JWT cookie**
   - Check `COOKIE_MAX_AGE` (default: 1800s = 30 min)
   - The filter should automatically refresh via the refresh token

2. **Expired refresh token**
   - Check that Keycloak has a large enough `Refresh Token Lifespan` value
   - The client must re-authenticate

3. **Invalid token**
   - Check that `KEYCLOAK_JWK_SET_URI` is correct
   - Check Gateway logs for a signature error

**Debug**:

```bash
# Check cookies
curl -v http://localhost:8080/api/auth/me

# View logs
mvn spring-boot:run | grep -i "jwt\|auth\|cookie"

# Test JWT validation
mvn test -Dtest=AuthCookieWebFilterTest
```

### Problem: CORS errors

**Solutions**:

1. **Check CORS config** in `SecurityConfig`:
   ```java
   .cors(Customizer.withDefaults())  // ✅ Enabled
   ```

2. **Custom configuration** in `CorsConfig.java`

3. **Response headers**:
   ```
   Access-Control-Allow-Origin: http://localhost:5173
   Access-Control-Allow-Credentials: true
   Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
   ```

### Problem: "host.docker.internal" not resolvable

**Docker on Windows/Mac**: `host.docker.internal` works natively.

**Docker on Linux**: Requires special configuration:

```bash
# Add to docker-compose.yml
extra_hosts:
  - "host.docker.internal:host-gateway"
  - "backend.local:host-gateway"
```

Or use the host IP directly:

```bash
BACKEND_URI=http://192.168.1.100:10020
```

### Problem: Keycloak not accessible

**Check**:

```bash
# Ping Keycloak
curl http://localhost:8085/realms/skillshub

# Check config
cat envs/dev/dev.env | grep KEYCLOAK

# Check Gateway logs
docker logs gateway-service | grep -i keycloak
```

### Problem: "Cannot resolve symbol" in IDE

```bash
# Regenerate sources
mvn clean generate-sources

# Reload Maven project (JetBrains IDE)
Ctrl+Shift+A > Reload project / Reimport Maven Changes
```

---

## Additional Resources

- [Spring Cloud Gateway Docs](https://spring.io/projects/spring-cloud-gateway)
- [Spring WebFlux Docs](https://spring.io/projects/spring-webflux)
- [Spring Security OAuth2 Docs](https://spring.io/projects/spring-security-oauth2-client)
- [Keycloak Admin Guide](https://www.keycloak.org/docs/latest/server_admin/)
- [JWT.io](https://jwt.io) - Online JWT decoder

---

## Support

For questions or issues:

1. Check this documentation and the `docs/PROJECT_STATE.md` file
2. Check service logs
3. Open an issue on the GitLab repository
4. Contact the dev team

---

## License

This project is part of the Skillshub infrastructure. See the LICENSE file in the parent repository.

---

**Last updated**: February 2026
**Status**: Production-ready
