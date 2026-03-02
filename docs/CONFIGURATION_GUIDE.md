# Configuration Guide - Gateway Service

## Table of Contents

- [Configuration Files](#configuration-files)
- [Environment Variables](#environment-variables)
- [Spring Profiles](#spring-profiles)
- [Keycloak Configuration](#keycloak-configuration)
- [Backend Configuration](#backend-configuration)
- [CORS Configuration](#cors-configuration)
- [Logging](#logging)
- [Monitoring and Metrics](#monitoring-and-metrics)

---

## Configuration Files

```
gateway/
├── src/main/resources/
│   ├── application.yml                    # Main configuration (shared)
│   └── application-prod.yml               # Production overrides
│
├── envs/
│   ├── dev/
│   │   ├── dev.env                        # Local dev variables
│   │   └── docker-hybrid.env              # Docker hybrid variables
│   └── prod/
│       └── prod.env                       # Prod variables (⚠️ secrets)
│
└── deploy/
    ├── envs/
    │   └── prod.env                       # Prod copy for deployment
    └── prod.docker-compose.yml            # Prod stack
```

### application.yml (main)

Located at: `src/main/resources/application.yml`

This is the **master** file that defines:

1. **Spring Boot core**
   ```yaml
   spring:
     application:
       name: gateway-service
     main:
       web-application-type: reactive
   ```

2. **Spring Cloud Gateway routes**
   ```yaml
   cloud:
     gateway:
       routes:
         - id: backend
           uri: ${BACKEND_URI:http://localhost:10020}
           predicates:
             - Path=/api/**
   ```

3. **Keycloak OAuth2 client**
   ```yaml
   security:
     oauth2:
       client:
         registration:
           keycloak:
             client-id: gateway-service
             ...
   ```

4. **Skillshub custom config**
   ```yaml
   skillshub:
     auth:
       cookie-name: SKILLSHUB_AUTH
       cookie-domain: ""
       ...
   ```

### Configuration Hierarchy

Spring loads in this **precedence order** (lowest to highest priority):

```
1️⃣ application.yml
        ↓ (overrides)
2️⃣ application-{profile}.yml  (e.g. application-prod.yml)
        ↓ (overrides)
3️⃣ Environment variables (env vars)
        ↓ (overrides)
4️⃣ .properties file launched via CLI
```

**Example**: `BACKEND_URI` can be defined at 4 levels:

```yaml
# 1️⃣ application.yml
app:
  backend:
    base-url: http://localhost:10020

# 2️⃣ application-prod.yml
app:
  backend:
    base-url: http://backend-service:10020

# 3️⃣ Env var at launch
export APP_BACKEND_BASE_URL=http://prod-backend:10020

# 4️⃣ .env file
APP_BACKEND_BASE_URL=http://prod-backend:10020
```

Resolution order:
- Local dev: `application.yml` + `dev.env`
- Docker hybrid: `application.yml` + `docker-hybrid.env`
- Production: `application-prod.yml` + `prod.env`

---

## Environment Variables

### Format

Spring converts **shell variables** to YAML properties:

```bash
# Shell/env var
KEYCLOAK_ISSUER_URI=http://localhost:8085/realms/skillshub

# Becomes in Spring
keycloak:
  issuer-uri: http://localhost:8085/realms/skillshub
```

Or with dot notation:

```bash
export SPRING_SECURITY_OAUTH2_PROVIDER_KEYCLOAK_ISSUER_URI=...
```

### Main Variables

| Variable | Default | Description |
|----------|---------|-------------|
| **SPRING_PROFILES_ACTIVE** | `docker-hybrid` | Active profile (dev, prod, docker-hybrid) |
| **SERVER_PORT** | `8080` | Gateway listening port |
| **SERVER_ADDRESS** | `0.0.0.0` | Listening address (0.0.0.0 = all interfaces) |
| **BACKEND_URI** | `http://localhost:10020` | Backend service URL |
| **KEYCLOAK_BASE_URL** | *required* | Keycloak URL (e.g. `http://localhost:8085`) |
| **KEYCLOAK_ISSUER_URI** | *required* | JWT issuer URI (e.g. `http://localhost:8085/realms/skillshub`) |
| **KEYCLOAK_AUTHORIZATION_URI** | *required* | Keycloak `/auth` endpoint URL |
| **KEYCLOAK_TOKEN_URI** | *required* | Keycloak `/token` endpoint URL |
| **KEYCLOAK_JWK_SET_URI** | *required* | Keycloak public key `/certs` URL |
| **KEYCLOAK_USER_INFO_URI** | *required* | Keycloak `/userinfo` endpoint URL |
| **KEYCLOAK_REALM** | `skillshub` | Keycloak realm |
| **COOKIE_SECURE** | `true` | HTTPS-only transmission |
| **COOKIE_SAME_SITE** | `None` | SameSite cookie flag |
| **COOKIE_MAX_AGE** | `1800` | Cookie TTL (in seconds) |
| **COOKIE_DOMAIN** | `` (empty) | Cookie domain (empty = host only) |
| **AUTH_REDIRECT_AFTER_LOGIN** | `http://localhost:5173/` | Redirect URL after login |
| **AUTH_REDIRECT_AFTER_LOGOUT** | `http://localhost:5173/` | Redirect URL after logout |

### Sample .env Files

#### dev.env (Local Development Mode)

```env
# ===============================================
# Spring Configuration
# ===============================================
SPRING_PROFILES_ACTIVE=dev

# ===============================================
# Server
# ===============================================
SERVER_ADDRESS=0.0.0.0
SERVER_PORT=8080

# ===============================================
# Backend Service
# ===============================================
BACKEND_URI=http://localhost:10020

# ===============================================
# Keycloak (in Docker on port 8085)
# ===============================================
KEYCLOAK_BASE_URL=http://localhost:8085
KEYCLOAK_ISSUER_URI=http://localhost:8085/realms/skillshub
KEYCLOAK_AUTHORIZATION_URI=http://localhost:8085/realms/skillshub/protocol/openid-connect/auth
KEYCLOAK_TOKEN_URI=http://localhost:8085/realms/skillshub/protocol/openid-connect/token
KEYCLOAK_JWK_SET_URI=http://localhost:8085/realms/skillshub/protocol/openid-connect/certs
KEYCLOAK_USER_INFO_URI=http://localhost:8085/realms/skillshub/protocol/openid-connect/userinfo
KEYCLOAK_REALM=skillshub

# ===============================================
# Cookies (Development mode - no HTTPS)
# ===============================================
COOKIE_SECURE=false
COOKIE_SAME_SITE=Lax
COOKIE_DOMAIN=
COOKIE_MAX_AGE=1800

# ===============================================
# Redirects
# ===============================================
AUTH_REDIRECT_AFTER_LOGIN=http://localhost:5173/
AUTH_REDIRECT_AFTER_LOGOUT=http://localhost:5173/

# ===============================================
# Keycloak Admin Access (for internal requests)
# ===============================================
KEYCLOAK_ADMIN_CLIENT_ID=admin-cli
KEYCLOAK_ADMIN_CLIENT_SECRET=your-secret-here
```

#### docker-hybrid.env (Gateway in Docker, local services)

```env
# ===============================================
# Spring Configuration
# ===============================================
SPRING_PROFILES_ACTIVE=docker-hybrid

# ===============================================
# Server
# ===============================================
SERVER_ADDRESS=0.0.0.0
SERVER_PORT=8080

# ===============================================
# Backend Service (accessible from container)
# ===============================================
# Note: host.docker.internal = host IP (Windows/Mac)
#       On Linux, see docker-compose extra_hosts
BACKEND_URI=http://host.docker.internal:10020

# ===============================================
# Keycloak (also on host)
# ===============================================
KEYCLOAK_BASE_URL=http://host.docker.internal:8085
KEYCLOAK_ISSUER_URI=http://host.docker.internal:8085/realms/skillshub
KEYCLOAK_AUTHORIZATION_URI=http://host.docker.internal:8085/realms/skillshub/protocol/openid-connect/auth
KEYCLOAK_TOKEN_URI=http://host.docker.internal:8085/realms/skillshub/protocol/openid-connect/token
KEYCLOAK_JWK_SET_URI=http://host.docker.internal:8085/realms/skillshub/protocol/openid-connect/certs
KEYCLOAK_USER_INFO_URI=http://host.docker.internal:8085/realms/skillshub/protocol/openid-connect/userinfo
KEYCLOAK_REALM=skillshub

# ===============================================
# Cookies
# ===============================================
COOKIE_SECURE=false
COOKIE_SAME_SITE=Lax
COOKIE_DOMAIN=
COOKIE_MAX_AGE=1800

# ===============================================
# Redirects
# ===============================================
AUTH_REDIRECT_AFTER_LOGIN=http://localhost:5173/
AUTH_REDIRECT_AFTER_LOGOUT=http://localhost:5173/

# ===============================================
# Keycloak Admin
# ===============================================
KEYCLOAK_ADMIN_CLIENT_ID=admin-cli
KEYCLOAK_ADMIN_CLIENT_SECRET=your-secret-here
```

#### prod.env (Production - CONFIDENTIAL ⚠️)

```env
# ⚠️ WARNING: This file contains secrets
# Do NOT commit to Git!

# ===============================================
# Spring Configuration
# ===============================================
SPRING_PROFILES_ACTIVE=prod

# ===============================================
# Server
# ===============================================
SERVER_ADDRESS=0.0.0.0
SERVER_PORT=8080

# ===============================================
# Backend Service (intra-Docker network)
# ===============================================
BACKEND_URI=http://backend-service:10020

# ===============================================
# Keycloak (public FQDN)
# ===============================================
KEYCLOAK_BASE_URL=https://keycloak.skillshub.io
KEYCLOAK_ISSUER_URI=https://keycloak.skillshub.io/realms/skillshub
KEYCLOAK_AUTHORIZATION_URI=https://keycloak.skillshub.io/realms/skillshub/protocol/openid-connect/auth
KEYCLOAK_TOKEN_URI=https://keycloak.skillshub.io/realms/skillshub/protocol/openid-connect/token
KEYCLOAK_JWK_SET_URI=https://keycloak.skillshub.io/realms/skillshub/protocol/openid-connect/certs
KEYCLOAK_USER_INFO_URI=https://keycloak.skillshub.io/realms/skillshub/protocol/openid-connect/userinfo
KEYCLOAK_REALM=skillshub

# ===============================================
# Cookies (HTTPS required)
# ===============================================
COOKIE_SECURE=true
COOKIE_SAME_SITE=None
COOKIE_DOMAIN=.skillshub.io
COOKIE_MAX_AGE=1800

# ===============================================
# Redirects
# ===============================================
AUTH_REDIRECT_AFTER_LOGIN=https://skillshub.io/
AUTH_REDIRECT_AFTER_LOGOUT=https://skillshub.io/

# ===============================================
# Keycloak Admin (Secrets - via vault)
# ===============================================
KEYCLOAK_ADMIN_CLIENT_ID=admin-cli
KEYCLOAK_ADMIN_CLIENT_SECRET=<generated-secret-from-vault>
```

---

## Spring Profiles

The Gateway uses **Spring profiles** to adapt configuration per environment.

### Available Profiles

| Profile | Use case | Keycloak | Backend | Cookies |
|---------|----------|----------|---------|---------|
| `dev` | Local Maven dev | `localhost:8085` | `localhost:10020` | `Lax`, no domain |
| `docker-hybrid` | Docker Gateway + local services | `host.docker.internal:8085` | `host.docker.internal:10020` | `Lax`, no domain |
| `docker-all` | All services in Docker | `keycloak:8085` | `backend-service:10020` | `Lax`, no domain |
| `prod` | Production | HTTPS FQDN | HTTPS FQDN | `None`, shared domain |

### How to Activate a Profile

#### With Maven

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="--spring.profiles.active=dev"
```

#### With Environment Variable

```bash
export SPRING_PROFILES_ACTIVE=prod
java -jar target/gateway-service-1.0.0-SNAPSHOT.jar
```

#### With Docker

```bash
docker run -e SPRING_PROFILES_ACTIVE=prod -p 8080:8080 gateway-service:latest
```

#### With docker-compose

```yaml
services:
  gateway-service:
    image: gateway-service:latest
    environment:
      SPRING_PROFILES_ACTIVE: prod
```

---

## Keycloak Configuration

### Required Keycloak Client

The Gateway requires a **Keycloak client** called `gateway-service`.

#### Create the Client

1. **Keycloak Admin Console** → `Clients` → `Create`
2. **Fill in the fields**:
   - **Client ID**: `gateway-service`
   - **Protocol**: `openid-connect`
   - **Client Type**: `public` (OAuth2)
   - **Valid Redirect URIs**:
     ```
     http://localhost:8080/login/oauth2/code/keycloak          (dev)
     https://skillshub.io/login/oauth2/code/keycloak           (prod)
     ```
   - **Web Origins**:
     ```
     http://localhost:5173                                      (frontend dev)
     https://skillshub.io                                      (frontend prod)
     ```

#### Scopes

Make sure `openid`, `profile`, `email` scopes are **enabled**:

1. Go to `Clients` → `gateway-service` → `Scopes`
2. Verify `openid`, `profile`, `email` are checked

#### Client Access

Keycloak automatically generates:

- **Client Secret** (for confidential clients, not needed here since it's public)
- **OIDC Discovery endpoint**: `http://localhost:8085/realms/skillshub/.well-known/openid-configuration`

### Verify Keycloak Config

#### Basic Access Test

```bash
# Verify Keycloak is accessible
curl http://localhost:8085/realms/skillshub

# Verify OIDC discovery
curl http://localhost:8085/realms/skillshub/.well-known/openid-configuration | jq .

# Output:
# {
#   "issuer": "http://localhost:8085/realms/skillshub",
#   "authorization_endpoint": "...",
#   "token_endpoint": "...",
#   "jwks_uri": "...",
#   ...
# }

# Verify public key (JWK)
curl http://localhost:8085/realms/skillshub/protocol/openid-connect/certs | jq .

# Output:
# {
#   "keys": [
#     {
#       "kid": "...",
#       "kty": "RSA",
#       "use": "sig",
#       "n": "...",
#       "e": "AQAB"
#     }
#   ]
# }
```

---

## Backend Configuration

### Gateway → Backend Route

The Gateway uses Spring Cloud Gateway to **route requests to the backend**.

In `application.yml`:

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: backend
          uri: ${BACKEND_URI:http://localhost:10020}
          order: 100
          predicates:
            - Path=/api/**
          filters:
            - StripPrefix=2  # Remove /api prefix before forwarding
```

### Test the Backend Connection

```bash
# 1. Verify the backend is accessible
curl http://localhost:10020/actuator/health
# Expected: {"status":"UP"}

# 2. Call via the Gateway (unprotected)
curl http://localhost:8080/api/public/courses
# Expected: 200 + data

# 3. Call via the Gateway (protected - without auth)
curl http://localhost:8080/api/courses
# Expected: 401 Unauthorized

# 4. Call via the Gateway (protected - with auth)
curl -b cookies.txt http://localhost:8080/api/courses
# Expected: 200 + data
# X-User-* headers are added automatically
```

### Headers Forwarded to the Backend

The Gateway automatically adds via `XUserHeadersFilter`:

```
X-User-Id: 550e8400-e29b-41d4-a716-446655440000
X-User-Email: john@example.com
X-User-Roles: STUDENT,TUTOR
```

The backend must **read these headers** to validate access.

---

## CORS Configuration

### Common CORS Problem

```
Error: Access to XMLHttpRequest blocked by CORS policy
```

### Configuration in SecurityConfig

```java
@Bean
public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    return http
        .cors(Customizer.withDefaults())  // ← Enable CORS
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .authorizeExchange(...)
        .build();
}
```

**`Customizer.withDefaults()` enables**:

- Methods: `GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`
- Headers: `Content-Type`, `Accept`, etc.
- Credentials: No (by default)

### Custom Configuration

If needed, create a `CorsConfigurationSource` bean:

```java
@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList(
            "http://localhost:5173",        // Frontend dev
            "https://skillshub.io"          // Frontend prod
        ));
        config.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "OPTIONS"
        ));
        config.setAllowedHeaders(Arrays.asList(
            "Content-Type", "Authorization"
        ));
        config.setAllowCredentials(true);   // Allow cookies
        config.setMaxAge(3600L);            // Preflight cache

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
```

---

## Logging

### Log Configuration

In `application.yml`:

```yaml
logging:
  level:
    root: INFO
    org.springframework.cloud.gateway: DEBUG
    org.springframework.security: DEBUG
    org.springframework.security.oauth2: TRACE
    reactor.netty.http.server: INFO
    com.skillshub.gateway_service: DEBUG
```

### Log Levels

| Level | Content |
|-------|---------|
| **TRACE** | Very verbose (token details, request/response bodies) |
| **DEBUG** | Execution details (filter runs, cache hits, routing decisions) |
| **INFO** | General info (startup, health, major events) |
| **WARN** | Warnings (deprecated config, potential issues) |
| **ERROR** | Errors (exceptions, failed connections) |

### Important: Logs to Watch

```bash
# JWT decoding errors
grep "Invalid JWT\|JWT\|decode" logs/*.log

# Refresh token issues
grep "Refresh failed\|Refresh success\|Access token expired" logs/*.log

# Cookie issues
grep "cookie\|SKILLSHUB_AUTH" logs/*.log

# Authentication issues
grep "Unauthorized\|401\|Authentication" logs/*.log

# Keycloak connection
grep "Keycloak\|OIDC\|issuer" logs/*.log
```

---

## Monitoring and Metrics

### Actuator Endpoints

The Gateway exposes operational information via `/actuator`.

#### Health Check

```bash
curl http://localhost:8080/actuator/health

# Output:
{
  "status": "UP",
  "components": {
    "diskSpace": {
      "status": "UP",
      "details": {"total": 1099511627776, "free": 549755813888}
    },
    "db": {"status": "UP"},
    "livenessState": {"status": "UP"},
    "readinessState": {"status": "UP"}
  }
}
```

#### Available Routes

```bash
curl http://localhost:8080/actuator/gateway/routes | jq .

# Output:
[
  {
    "route_id": "backend",
    "route_definition": {
      "id": "backend",
      "uri": "http://localhost:10020",
      "predicates": [{"name": "Path", "args": {"_genkey_0": "/api/**"}}],
      "filters": [{"name": "StripPrefix", "args": {"_genkey_0": "2"}}],
      "order": 100
    },
    "order": 100
  }
]
```

#### Info Endpoint

```bash
curl http://localhost:8080/actuator/info | jq .

# Output:
{
  "app": {
    "name": "gateway-service",
    "description": "Skillshub API Gateway",
    "version": "1.0.0-SNAPSHOT",
    "encoding": "UTF-8",
    "java": {
      "source": "21",
      "target": "21"
    }
  },
  "build": {
    "timestamp": "2026-02-15T10:30:00Z",
    "version": "1.0.0-SNAPSHOT"
  }
}
```

### Micrometer Metrics

If Micrometer is enabled (not enabled by default):

```bash
# HTTP metrics
curl http://localhost:8080/actuator/metrics/http.server.requests

# JVM metrics
curl http://localhost:8080/actuator/metrics/jvm.memory.used

# Custom metrics
curl http://localhost:8080/actuator/metrics/custom.auth.refresh.success
```

### Production Logging

In production, send logs to a centralized system:

```yaml
logging:
  file:
    name: /var/log/gateway/application.log
    max-size: 10MB
    max-history: 10
  pattern:
    file: "%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n"
    console: "%d{HH:mm:ss} %highlight(%-5level) %logger{36} - %msg%n"
```

---

## Sensitive Security Configuration

### Secrets to Protect

- `KEYCLOAK_ADMIN_CLIENT_SECRET`
- All Keycloak JWKs/private keys
- Backend access credentials
- API keys/authentication tokens

### Secret Management

**Development**:
- Local `.env` files (`.gitignore`)
- Session environment variables

**Production**:
- Vault (HashiCorp Vault)
- Cloud Secrets Manager (AWS Secrets Manager, Azure Key Vault, etc.)
- Never in Git or Docker images

### Example with Vault

```bash
# Inject secrets from Vault at startup
docker run -e VAULT_ADDR=https://vault.example.com \
           -e VAULT_TOKEN=<token> \
           -v vault-config:/etc/vault \
           gateway-service:latest
```

---

**Last updated**: February 2026
