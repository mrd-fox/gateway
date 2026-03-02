# FAQ - Gateway Service

## Frequently Asked Questions

### Authentication & Cookies

#### Q: Why is my authentication cookie deleted immediately?

**A:** Check several possible causes:

1. **SameSite=None without Secure=true** → Browser rejects it
   ```yaml
   # ❌ WRONG
   COOKIE_SECURE=false
   COOKIE_SAME_SITE=None

   # ✅ CORRECT (local dev)
   COOKIE_SECURE=false
   COOKIE_SAME_SITE=Lax

   # ✅ CORRECT (prod)
   COOKIE_SECURE=true
   COOKIE_SAME_SITE=None
   ```

2. **Domain mismatch** → Cookie not sent
   ```bash
   # Verify the browser uses the same domain
   curl -v http://localhost:8080/api/auth/me

   # View Set-Cookie headers
   # Do not use 127.0.0.1 with localhost
   ```

3. **Max-Age=0 immediately after** → Cookie cleared
   ```bash
   # Check logs for double Set-Cookie
   grep "Set-Cookie.*Max-Age" logs/*.log

   # If two Set-Cookie appear: create + clear = conflict
   ```

---

#### Q: How do I reduce cookie TTL to test the refresh flow?

**A:** Modify `COOKIE_MAX_AGE` (in seconds):

```bash
# Default: 1800 seconds (30 min)
COOKIE_MAX_AGE=1800

# For quick testing (2 minutes)
COOKIE_MAX_AGE=120

# Then make a call after 2 min
sleep 120
curl -b cookies.txt http://localhost:8080/api/users/me
# The filter detects expiration and performs an automatic refresh
```

---

#### Q: What is the difference between `COOKIE_MAX_AGE` and the JWT TTL?

**A:** Two independent things:

| Aspect | Cookie Max-Age | JWT TTL |
|--------|----------------|---------|
| Stored in | Browser (HTTP cookie) | JWT claims (`exp`) |
| Defined by | Gateway (`COOKIE_MAX_AGE`) | Keycloak (token lifespan) |
| Expiration | Browser-side (deletion) | Server validation (JWT invalid) |
| Behavior | Browser deletes the cookie | Gateway rejects the token |

**Example**:
```
- COOKIE_MAX_AGE=1800 (30 min)
- JWT TTL=3600 (1 hour)

Timeline:
  00:00 → Login. Both set.
  30:00 → Browser deletes cookie. Gateway returns 401 (no cookie).
  60:00 → JWT claim exp reached. (But cookie already gone, so ignored.)
```

**Best practice**: Align both values, or set `JWT TTL > COOKIE_MAX_AGE` to leave time for refresh.

---

#### Q: How do I test the login flow manually?

**A:** Complete steps:

```bash
# 1. Initiate login (redirects to Keycloak)
curl -i -L http://localhost:8080/api/auth/login
# You are redirected to the Keycloak /auth endpoint

# 2. Login on Keycloak (manual via browser)
# Go to http://localhost:8080/api/auth/login in the browser
# Keycloak asks for username/password
# You are redirected to /login/oauth2/code/keycloak?code=XXX

# 3. Retrieve the cookie (automatically stored by browser)
# Check in DevTools → Application → Cookies
# You should see:
#   - SKILLSHUB_AUTH=<JWT access token>
#   - SKILLSHUB_AUTH_RT=<JWT refresh token>

# 4. Call a protected route
curl -b "SKILLSHUB_AUTH=<your-token>" http://localhost:8080/api/users/me
# Expected: 200 + user data
```

---

### Configuration & Variables

#### Q: Where do I place the `.env` file so it is loaded automatically?

**A:** Spring does **not** automatically load `.env` files. Options:

**Option 1: Via command line** (recommended)

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="--spring.config.additional-location=file:envs/dev/dev.env"

# Or
java -jar target/gateway-service-1.0.0-SNAPSHOT.jar \
  --spring.config.additional-location=file:envs/dev/dev.env
```

**Option 2: Load in the shell then run**

```bash
# Linux/Mac
set -a
source envs/dev/dev.env
set +a
mvn spring-boot:run

# Windows PowerShell
Get-Content envs/dev/dev.env | ForEach-Object {
  if ($_ -notmatch "^#" -and $_ -match "=") {
    $var = $_.Split("=", 2)
    [Environment]::SetEnvironmentVariable($var[0], $var[1])
  }
}
mvn spring-boot:run
```

**Option 3: Docker (automatic)**

```yaml
services:
  gateway:
    env_file: envs/dev/docker-hybrid.env  # ← Loaded automatically
```

---

#### Q: How do I verify which config is active?

**A:** Several ways:

```bash
# 1. Actuator info endpoint
curl http://localhost:8080/actuator/info | jq '.app'
# Output: name, version, etc.

# 2. Startup logs
mvn spring-boot:run 2>&1 | head -30
# Look for: "Active profiles: dev" or "Active profiles: prod"

# 3. Via HTTP
curl http://localhost:8080/actuator/env | jq '.propertySources[] | select(.name == "systemEnvironment")'

# 4. Application logs
tail -f logs/application.log
```

---

#### Q: Can I have multiple active profiles simultaneously?

**A:** Yes, but mind the order:

```bash
# ✅ CORRECT: dev AND custom
SPRING_PROFILES_ACTIVE=dev,custom

# ❌ CAUTION: order matters
# If dev AND prod have the same property, the last one wins
SPRING_PROFILES_ACTIVE=dev,prod  # prod.yml overrides dev.yml
```

---

### Routes & Routing

#### Q: How do I add a new protected route to the backend?

**A:** Edit `application.yml`:

```yaml
spring:
  cloud:
    gateway:
      routes:
        # Existing route
        - id: backend
          uri: ${BACKEND_URI:http://localhost:10020}
          predicates:
            - Path=/api/**
          order: 100

        # ← New route
        - id: my-new-service
          uri: http://my-service:9000
          predicates:
            - Path=/api/my-feature/**
          filters:
            - StripPrefix=2
          order: 50  # Higher order = higher priority
```

Automatically protected by:
- `AuthCookieWebFilter` → Validates JWT from cookie
- `XUserHeadersFilter` → Adds X-User-* headers

---

#### Q: How do I create a public route (without auth)?

**A:** Declare in the route AND in the filter:

```yaml
# 1. In application.yml (declare the route)
- id: public-api
  uri: ${BACKEND_URI}
  predicates:
    - Path=/api/public/**
  order: 10  # High priority
```

```java
// 2. In SecurityConfig.authorizeExchange()
.pathMatchers("/api/public/**").permitAll()
```

```java
// 3. In XUserHeadersFilter.isPublicApi()
private boolean isPublicApi(String path) {
    return path != null && path.startsWith("/api/public/");
}
```

---

#### Q: Why is my route not responding?

**A:** Check route order:

```yaml
# Routes are matched IN ORDER
# The first match wins

routes:
  - id: specific-route      # order: 10 (matched first)
    predicates:
      - Path=/api/users/admin/**

  - id: generic-route       # order: 100 (matched second)
    predicates:
      - Path=/api/users/**
```

**Debug**:

```bash
# View active routes
curl http://localhost:8080/actuator/gateway/routes | jq '.[] | {id, order, predicates}'

# Routing logs
mvn spring-boot:run 2>&1 | grep -i "route\|predicate\|match"
```

---

### Keycloak & OAuth2

#### Q: How do I generate `KEYCLOAK_ADMIN_CLIENT_SECRET`?

**A:** Via Keycloak Admin Console:

1. **Keycloak Admin Console** → `Clients` → Find an admin client
2. **Select the client** (e.g. `admin-cli`)
3. **"Credentials" tab** → Click "Regenerate Secret"
4. **Copy the secret** → Add to `.env`

Or via API:

```bash
# Login
TOKEN=$(curl -X POST http://localhost:8085/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" | jq -r '.access_token')

# Regenerate secret
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:8085/admin/realms/skillshub/clients/CLIENT_ID/client-secret

# Output: {"type":"client_jwt","algorithm":"HS256","secret":"..."}
```

---

#### Q: My `KEYCLOAK_ISSUER_URI` produces 401 errors. How do I test?

**A:** Check each part of the URL:

```bash
# 1. Is Keycloak accessible?
curl http://localhost:8085/
# Expected: 200 (Keycloak HTML)

# 2. Does the realm exist?
curl http://localhost:8085/realms/skillshub
# Expected: 200 (realm XML info)

# 3. Does the OIDC discovery endpoint work?
curl http://localhost:8085/realms/skillshub/.well-known/openid-configuration
# Expected: 200 + JSON with issuer, endpoints, keys_uri, etc.

# 4. Is the public key accessible?
curl http://localhost:8085/realms/skillshub/protocol/openid-connect/certs
# Expected: 200 + JSON with RSA keys

# 5. Is the token endpoint accessible?
curl http://localhost:8085/realms/skillshub/protocol/openid-connect/token
# Expected: 405 (POST required) or 400 (missing params)
# NOT 404 (404 = endpoint doesn't exist)
```

---

#### Q: JWT decoding fails. How do I debug the signature?

**A:** Decode and verify manually:

```bash
# 1. Extract the token from the cookie
TOKEN="eyJhbGciOiJSUzI1NiIs..."

# 2. Decode on https://jwt.io
# Paste the full token into https://jwt.io
# Check claims (sub, email, exp, etc.)

# 3. Verify the signature
# For JWT, Keycloak uses RSA256
# Go to https://jwt.io and paste the Keycloak public key

# 4. Download the Keycloak public key
curl http://localhost:8085/realms/skillshub/protocol/openid-connect/certs \
  | jq '.keys[0]' > keycloak-key.json

# 5. Run the Gateway with TRACE logging
export SPRING_SECURITY_OAUTH2_PROVIDER_KEYCLOAK_ISSUER_URI=http://localhost:8085/realms/skillshub
mvn spring-boot:run 2>&1 | grep -i "rsa\|signature\|verification"
```

---

### Docker & Deployment

#### Q: Error `host.docker.internal` not resolvable on Linux

**A:** `host.docker.internal` only works on Docker Desktop (Windows/Mac).

On Linux, add to `docker-compose.yml`:

```yaml
services:
  gateway-service:
    # ...
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

Or use the host IP:

```bash
# Find the host IP
hostname -I
# Output: 192.168.1.100

# Use this IP
BACKEND_URI=http://192.168.1.100:10020
```

---

#### Q: How do I rebuild the Docker image after a code change?

**A:** Complete steps:

```bash
# 1. Stop containers
docker-compose down

# 2. Remove the old image
docker rmi gateway-service:latest

# 3. Rebuild
docker-compose build --no-cache

# 4. Restart
docker-compose up -d

# 5. Verify
docker logs -f gateway-service
```

---

#### Q: How do I pass environment variables in production?

**A:** Several options:

**Option 1: .env file with docker-compose**

```yaml
services:
  gateway-service:
    env_file: deploy/envs/prod.env  # ← Spring loads automatically
```

**Option 2: Variables in docker-compose.yml**

```yaml
services:
  gateway-service:
    environment:
      SPRING_PROFILES_ACTIVE: prod
      BACKEND_URI: http://backend-service:10020
      KEYCLOAK_ISSUER_URI: https://keycloak.skillshub.io/realms/skillshub
```

**Option 3: Secret management (Vault, AWS Secrets Manager)**

```bash
# Via Docker Secrets (Swarm mode)
docker secret create db_password -
# ... or via Kubernetes Secrets, Vault, etc.
```

---

### Logs & Debugging

#### Q: How do I enable debug logs for a specific class?

**A:** Use `application.yml`:

```yaml
logging:
  level:
    com.skillshub.gateway_service: DEBUG
    com.skillshub.gateway_service.auth.filter: TRACE
    org.springframework.security: DEBUG
    org.springframework.cloud.gateway: DEBUG
```

Or via variable:

```bash
export LOGGING_LEVEL_COM_SKILLSHUB_GATEWAY_SERVICE=DEBUG
java -jar target/gateway-service-1.0.0-SNAPSHOT.jar
```

---

#### Q: Where are logs stored in production?

**A:** By default: stdout/Docker logs

```bash
# View logs in real time
docker logs -f gateway-service

# Save to file
docker logs gateway-service > logs.txt

# Config for file logging
docker run -v /var/log:/app/logs \
  -e LOGGING_FILE_NAME=/app/logs/gateway.log \
  gateway-service:latest
```

---

#### Q: How do I filter logs to find a specific error?

**A:** Use `grep`:

```bash
# Authentication errors
docker logs gateway-service | grep -i "unauthorized\|401\|authentication"

# JWT issues
docker logs gateway-service | grep -i "jwt\|decode\|invalid.*token"

# Keycloak issues
docker logs gateway-service | grep -i "keycloak\|issuer\|oidc"

# Refresh token issues
docker logs gateway-service | grep -i "refresh.*fail\|refresh.*success"

# All logs since container started
docker logs gateway-service 2>&1 | tail -100
```

---

### Performance & Scalability

#### Q: How do I verify the Gateway handles reactive requests properly?

**A:** Load test:

```bash
# Install Apache Bench
apt-get install apache2-utils  # Linux
brew install httpd             # Mac

# Load the Gateway
ab -n 1000 -c 50 http://localhost:8080/actuator/health
# -n: 1000 requests
# -c: 50 concurrent requests

# Check logs
# No "thread pool exhausted" = good sign
docker logs gateway-service | grep -i "thread\|reactor\|pool"
```

---

#### Q: Can the Gateway be horizontally scaled?

**A:** Yes, with load balancing. Architecture:

```
┌─────────────────────────────────────────┐
│       Load Balancer (Caddy, Nginx)      │
│  (sticky sessions for cookies)          │
└─────────────┬─────────────┬─────────────┘
              │             │
        ┌─────▼──────┐ ┌──▼──────────┐
        │ Gateway #1 │ │ Gateway #2  │
        │ :8080      │ │ :8081       │
        └─────┬──────┘ └──┬──────────┘
              │           │
              └─────┬─────┘
                    │
            ┌───────▼───────┐
            │  Backend (1)  │
            │  Keycloak (1) │
            └───────────────┘
```

docker-compose configuration:

```yaml
services:
  gateway-1:
    image: gateway-service:latest
    environment:
      SERVER_PORT: 8080

  gateway-2:
    image: gateway-service:latest
    environment:
      SERVER_PORT: 8081

  load-balancer:
    image: caddy:latest
    ports:
      - "80:80"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
```

---

### Integration with Other Services

#### Q: How do I call a Gateway API from the Backend?

**A:** Avoid infinite loops. The Backend should call **other services directly**, not through the Gateway:

```
WRONG (loop):
Frontend → Gateway → Backend1 → Gateway → Backend2 → Backend1

CORRECT (direct):
Frontend → Gateway → Backend1
Backend1 → Backend2 (direct, not via Gateway)
```

**In practice**:

```java
// ❌ WRONG
String url = "http://gateway-service:8080/api/users/" + userId;
user = restTemplate.getForObject(url, User.class);

// ✅ CORRECT
String url = "http://backend-service:10020/api/internal/users/" + userId;
user = restTemplate.getForObject(url, User.class);
// Note: /api/internal/* = internal endpoints, not via Gateway
```

---

## Need More Help?

- Check `README.md` for an overview
- Check `DEVELOPER_GUIDE.md` for technical concepts
- Check `CONFIGURATION_GUIDE.md` for detailed configuration
- Look at service logs
- Contact the dev team

---

**Last updated**: February 2026
