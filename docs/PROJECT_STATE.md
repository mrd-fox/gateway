# Gateway Update – Trusted Identity Propagation Hardening

Last update: 2026-02-15

---

## Context

The Gateway propagates authenticated user identity to backend services using internal headers:

- `X-User-Id`
- `X-User-Email`
- `X-User-Roles`

These headers are consumed by backend modules (e.g., Course module for entitlement enforcement).

Previously, the `XUserHeadersFilter` contained a bypass mechanism:

```java
String existingUserId = exchange.getRequest().getHeaders().getFirst(HEADER_USER_ID);
if (!isBlank(existingUserId)) {
    return chain.filter(exchange);
}
```

This meant that if a client manually sent `X-User-*` headers, the Gateway would trust and forward them unchanged.

---

## Security Issue Identified

With the introduction of entitlement enforcement in:

```
POST /api/courses/search
```

The backend now relies on `X-User-Id` to determine which courses a user is allowed to retrieve.

If a malicious client supplied a forged `X-User-Id` header:

- The Gateway would forward it.
- The backend would load enrollments for the forged user.
- Unauthorized data could be exposed.

This is a classic **header spoofing vulnerability**.

---

## Design Decision

### Trusted Identity Model

- **Keycloak** = Identity authority.
- **Gateway SecurityContext** = Runtime source of truth.
- `X-User-*` headers = Internal propagation mechanism only.

Client-supplied `X-User-*` headers must never be trusted.

---

## Implemented Fix

The Gateway now:

1. Always ignores client-supplied `X-User-*` headers.
2. Explicitly removes any incoming `X-User-*` values.
3. Injects trusted values derived from the authenticated SecurityContext.
4. Optionally logs spoof attempts.

### Updated Behavior (Protected Routes Only)

For protected routes:

```java
    h.remove(HEADER_USER_ID);
    h.remove(HEADER_USER_EMAIL);
    h.remove(HEADER_USER_ROLES);
    
    h.set(HEADER_USER_ID, userId);
    h.set(HEADER_USER_EMAIL, email);
    h.set(HEADER_USER_ROLES, roles);
```

This guarantees:

- Identity propagation is fully controlled by the Gateway.
- No client can impersonate another user via headers.
- Backend modules can safely trust `X-User-*`.

---

## Public Route Safety

The change does NOT affect public routes.

The filter still bypasses:

- `/api/public/**`
- `/api/auth/**`
- `/login/oauth2/**`
- `/oauth2/**`
- `/api/users/**` (per current contract)

Public APIs remain:

- Accessible without authentication.
- Unmodified by identity header injection.

---

## Impact Assessment

| Area | Impact |
|------|--------|
| UI normal flow | No impact |
| Authenticated requests | No impact |
| Entitlement enforcement | Secured |
| Public APIs | No impact |
| Backend contract | Strengthened |

---

## Risk of Breaking Communication

This change does NOT break normal communication flow because:

- The UI never legitimately sets `X-User-*`.
- All authenticated requests already rely on cookies.
- The Gateway continues to inject headers for protected routes.
- Only malicious or unintended client-supplied headers are overridden.

---

## Final Architecture State

The Gateway now enforces a strict boundary:

Client → Gateway (authentication via cookie)  
Gateway → Backend (trusted identity via injected headers)

This aligns with:

- Zero-trust header model
- Fail-closed entitlement enforcement
- Clean separation of responsibility

The system remains:

- Secure
- Modulith-consistent
- Hexagonally compliant
- IAM-aligned
