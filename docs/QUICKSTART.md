# QUICKSTART - Gateway Service

**For the impatient: up and running in 10 minutes**

## Installation (2 min)

```bash
# 1. Enter the directory
cd gateway

# 2. Check prerequisites
java -version          # Java 21+
mvn --version          # Maven 3.9+
docker --version       # Docker (optional)
```

## Local Configuration (3 min)

**Option A: Local development mode (simpler)**

```bash
# Create/edit envs/dev/dev.env
SPRING_PROFILES_ACTIVE=dev
SERVER_PORT=8080
BACKEND_URI=http://localhost:10020
KEYCLOAK_ISSUER_URI=http://localhost:8085/realms/skillshub
KEYCLOAK_AUTHORIZATION_URI=http://localhost:8085/realms/skillshub/protocol/openid-connect/auth
KEYCLOAK_TOKEN_URI=http://localhost:8085/realms/skillshub/protocol/openid-connect/token
KEYCLOAK_JWK_SET_URI=http://localhost:8085/realms/skillshub/protocol/openid-connect/certs
KEYCLOAK_USER_INFO_URI=http://localhost:8085/realms/skillshub/protocol/openid-connect/userinfo
COOKIE_SECURE=false
COOKIE_SAME_SITE=Lax
AUTH_REDIRECT_AFTER_LOGIN=http://localhost:5173/
AUTH_REDIRECT_AFTER_LOGOUT=http://localhost:5173/
KEYCLOAK_BASE_URL=http://localhost:8085
KEYCLOAK_REALM=skillshub
KEYCLOAK_ADMIN_CLIENT_ID=admin-cli
KEYCLOAK_ADMIN_CLIENT_SECRET=<secret>
```

**Option B: Docker hybrid mode (Docker Gateway + local services)**

```bash
# Use envs/dev/docker-hybrid.env (already set up)
# Just edit KEYCLOAK_ADMIN_CLIENT_SECRET if needed
```

## Start (3 min)

### Maven (local dev)

```bash
# Build
mvn clean install

# Run
java -jar target/gateway-service-1.0.0-SNAPSHOT.jar \
  --spring.config.additional-location=file:envs/dev/dev.env
```

### Docker (hybrid)

```bash
# Build the image
docker build -t gateway-service:latest .

# Start
docker-compose up --build
```

### Verify it works

```bash
curl http://localhost:8080/actuator/health
# Expected: {"status":"UP"}

curl http://localhost:8080/actuator/gateway/routes
# Expected: JSON with routes
```

## Quick Test (2 min)

```bash
# 1. Login (in the browser)
# On Mac/Linux:
open http://localhost:8080/api/auth/login
# On Windows:
start http://localhost:8080/api/auth/login

# 2. Keycloak credentials
# username: (your user)
# password: (your password)

# 3. After login, you are redirected with cookies set

# 4. Test a protected route
curl -b cookies.txt http://localhost:8080/api/users/me
# Expected: 200 + {"id": "...", "email": "..."}
```

## Useful Commands

```bash
# View logs
mvn spring-boot:run 2>&1 | tail -50

# Test Keycloak connection
curl http://localhost:8085/realms/skillshub

# View active variables
curl http://localhost:8080/actuator/env | jq '.propertySources[] | {name: .name, source: .source}'

# Stop Docker
docker-compose down

# Full rebuild
mvn clean install && docker build -t gateway-service:latest . && docker-compose up
```

## Common Issues

| Problem | Solution |
|---------|----------|
| `401 Unauthorized` | Check Keycloak is accessible. Re-run login. |
| Port 8080 already in use | Change `SERVER_PORT=8081` in .env |
| JWT validation error | Check `KEYCLOAK_JWK_SET_URI`. Test: `curl <url>` |
| `host.docker.internal` not found | On Linux, add to docker-compose.yml: `extra_hosts: - "host.docker.internal:host-gateway"` |
| Missing logs | Add `mvn spring-boot:run 2>&1 | tee logs.txt` |

**Need more details?** → [README.md](../README.md) or [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md)

## Essential Docs

- **[README.md](../README.md)** - Full project overview
- **[CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md)** - Detailed configuration
- **[FAQ.md](FAQ.md)** - Answers to your questions
- **[DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md)** - For implementing features

---

**You're all set!** Refer to [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) to navigate the docs.
