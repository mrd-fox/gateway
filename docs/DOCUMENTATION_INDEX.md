# Gateway Service Documentation - Complete Index

## Quick Overview

Welcome to the **Gateway Service** documentation, the centralized API entry point of the Skillshub infrastructure.

### Get Started Quickly?

1. **Are you a developer?** → See [README.md - "Starting the Service" section](../README.md#starting-the-service)
2. **Are you managing infrastructure?** → See [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md)
3. **Do you have a question?** → See [FAQ.md](FAQ.md)
4. **Are you developing a feature?** → See [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md)

---

## Available Documents

### 1. [README.md](../README.md) - **READ FIRST**

**Contents**:
- Project overview and global architecture
- Infrastructure context (integration with 3 other services)
- Technology stack and dependencies
- Installation and startup guide
- Complete authentication flow
- Cookie and session management
- Prerequisites and initial configuration
- Troubleshooting common problems

**For**: Everyone. Start here to understand the project.

**Reading time**: 20-30 minutes

---

### 2. [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) - For Developers

**Contents**:
- Key concepts (Spring WebFlux, reactive filters, etc.)
- Internal filter architecture
- Detailed authentication flow (step-by-step)
- Token and refresh management
- Security: header spoofing prevention
- Development recipes (add routes, endpoints, etc.)
- Debugging JWT and tokens
- Known issues and solutions

**For**: Java/Spring developers working on the Gateway

**Reading time**: 45-60 minutes

**Key sections**:
- [Key Concepts](#key-concepts) - Understanding WebFlux
- [Filter Architecture](#filter-architecture) - Filter chain
- [Authentication Management](#authentication-management) - Detailed OAuth2 flow
- [Development Recipes](#development-recipes) - How to implement

---

### 3. [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md) - For Administrators

**Contents**:
- Configuration file structure
- Environment variables (complete with examples)
- Spring profiles (dev, prod, docker, etc.)
- Keycloak configuration (client creation, scopes, etc.)
- Backend configuration
- CORS and security
- Logging in detail
- Monitoring and actuator endpoints
- Secret management

**For**: DevOps, system administrators, SREs

**Reading time**: 30-40 minutes

**Key sections**:
- [Environment Variables](#environment-variables) - All env vars explained
- [Spring Profiles](#spring-profiles) - dev vs prod
- [Keycloak Configuration](#keycloak-configuration) - Create and configure Keycloak client

---

### 4. [FAQ.md](FAQ.md) - Questions Answered

**Contents**:
- 40+ Q&A on:
  - Authentication and cookies
  - Configuration and variables
  - Routes and routing
  - Keycloak and OAuth2
  - Docker and deployment
  - Logs and debugging
  - Performance and scalability

**For**: Anyone with a specific question

**Reading time**: 15-30 minutes (consult as needed)

---

### 5. [analyse.md](../analyse.md) - In-Depth Technical Analysis

**Contents**:
- Detailed analysis of the authentication issue (February 2026)
- Problem: double Set-Cookie
- Location of problematic code
- Debugging approach
- Fix implementations

**For**: Developers debugging advanced authentication issues

**Reading time**: 15-20 minutes

---

### 6. [docs/PROJECT_STATE.md](PROJECT_STATE.md) - Project State

**Contents**:
- Gateway functional context
- Identified security issues
- Design decisions (Trusted Identity Model)
- Implemented fix for header spoofing
- Security guarantees

**For**: Security leads, architects

**Reading time**: 10-15 minutes

---

## Navigation Map by Role

### Java/Spring Developer

```
1. README.md (sections: Overview, Technical Architecture)
2. DEVELOPER_GUIDE.md (Key Concepts, Filter Architecture)
3. README.md (Developer Guide, Add a New Route)
4. FAQ.md (as needed)
```

### System Administrator / DevOps

```
1. README.md (sections: Overview, Deployment)
2. CONFIGURATION_GUIDE.md (all, top to bottom)
3. CONFIGURATION_GUIDE.md (Keycloak Configuration if needed)
4. FAQ.md (Docker & Deployment)
```

### Security Lead

```
1. docs/PROJECT_STATE.md (State and security)
2. DEVELOPER_GUIDE.md (Security: Header Spoofing)
3. CONFIGURATION_GUIDE.md (Sensitive Security Configuration)
4. README.md (Header Spoofing Prevention)
```

### New Developer (Onboarding)

```
1. README.md (EVERYTHING - 30 min)
   ├─ Overview
   ├─ Technical Architecture
   ├─ Installation and Configuration
   └─ Starting the Service
2. DEVELOPER_GUIDE.md (Key Concepts + Recipes - 30 min)
3. FAQ.md (Browse common questions - 10 min)
4. Clone the repo and do a local test
```

### Someone Debugging a Problem

```
1. Identify the symptom
2. Go to FAQ.md → Search for the symptom
3. If not found:
   - For auth issues → DEVELOPER_GUIDE.md (Authentication Management)
   - For config issues → CONFIGURATION_GUIDE.md
   - For code bugs → DEVELOPER_GUIDE.md + analyse.md
```

---

## Index of Key Sections

### Authentication

- [README.md: Authentication Flow](../README.md#authentication-flow)
- [DEVELOPER_GUIDE.md: Complete Login/Token/Refresh Flow](DEVELOPER_GUIDE.md#complete-logintokenrefresh-flow)
- [FAQ.md: Authentication Questions](FAQ.md#authentication--cookies)

### Configuration

- [CONFIGURATION_GUIDE.md: Environment Variables](CONFIGURATION_GUIDE.md#environment-variables)
- [CONFIGURATION_GUIDE.md: Sample .env Files](CONFIGURATION_GUIDE.md#sample-env-files)
- [README.md: Installation and Configuration](../README.md#installation-and-configuration)

### Keycloak

- [CONFIGURATION_GUIDE.md: Keycloak Configuration](CONFIGURATION_GUIDE.md#keycloak-configuration)
- [FAQ.md: Keycloak Questions](FAQ.md#keycloak--oauth2)
- [README.md: Keycloak Configuration](../README.md#3-keycloak-configuration)

### Docker & Deployment

- [README.md: Deployment](../README.md#deployment)
- [CONFIGURATION_GUIDE.md: Spring Profiles](CONFIGURATION_GUIDE.md#spring-profiles)
- [FAQ.md: Docker & Deployment](FAQ.md#docker--deployment)

### Security

- [DEVELOPER_GUIDE.md: Header Spoofing](DEVELOPER_GUIDE.md#security-header-spoofing)
- [docs/PROJECT_STATE.md: Security Analysis](PROJECT_STATE.md)
- [README.md: Security](../README.md#security)

### Debugging & Logs

- [CONFIGURATION_GUIDE.md: Logging](CONFIGURATION_GUIDE.md#logging)
- [FAQ.md: Logs & Debugging](FAQ.md#logs--debugging)
- [DEVELOPER_GUIDE.md: Debug a JWT Problem](DEVELOPER_GUIDE.md#debug-a-jwt-problem)

### Routing

- [README.md: Add a New Route](../README.md#adding-a-new-route)
- [DEVELOPER_GUIDE.md: Add a Protected Route](DEVELOPER_GUIDE.md#add-a-new-protected-route)
- [FAQ.md: Routes & Routing](FAQ.md#routes--routing)

---

## Document Summary

| Doc | Audience | Size | Reading Time | Priority |
|-----|----------|------|--------------|----------|
| README.md | Everyone | ~24 KB | 20-30 min | ESSENTIAL |
| DEVELOPER_GUIDE.md | Dev | ~20 KB | 45-60 min | Required for dev |
| CONFIGURATION_GUIDE.md | DevOps/Admin | ~22 KB | 30-40 min | Required for ops |
| FAQ.md | Everyone | ~18 KB | Variable | Consult as needed |
| analyse.md | Advanced dev | ~12 KB | 15-20 min | Optional |
| PROJECT_STATE.md | Arch/Security | ~5 KB | 10-15 min | Important context |

---

## How to Use This Documentation

### Scenario 1: I'm new to the project
```
1. Read README.md in full (30 min)
2. Read DEVELOPER_GUIDE.md - Key Concepts (15 min)
3. Do a first local test (30 min)
4. Keep FAQ.md handy
```

### Scenario 2: I have a specific error
```
1. Go to FAQ.md
2. Search for the symptom (Ctrl+F)
3. If found → Follow the answer
4. If not found →
   - Check service logs
   - Consult DEVELOPER_GUIDE.md or CONFIGURATION_GUIDE.md
   - Ask the team
```

### Scenario 3: I'm implementing a feature
```
1. Consult README.md - Developer Guide
2. Consult DEVELOPER_GUIDE.md - Development Recipes
3. Implement and test locally
4. Consult FAQ.md if issues arise
```

### Scenario 4: I'm deploying to production
```
1. Read CONFIGURATION_GUIDE.md - Environment Variables
2. Prepare the production .env file
3. Consult CONFIGURATION_GUIDE.md - Secret Management
4. Do a staging deployment test
5. Deploy to production
```

---

## Versions and Updates

| Date | Version | Changes |
|------|---------|---------|
| **2026-02-15** | **1.0.0** | Complete documentation (README, DEVELOPER_GUIDE, CONFIGURATION_GUIDE, FAQ) |

---

## Support and Contribution

- **Issues/Questions**: GitLab repository
- **Discussions**: Slack #gateway-dev
- **Documentation**: This INDEX.md + the 4 main guides

To **contribute** to the documentation:
1. Edit the appropriate document
2. Review your changes
3. Commit with an explicit message
4. Update the table in the "Versions and Updates" section

---

## Understanding Checklist (test your understanding)

After reading the documentation:

- [ ] I understand the role of the Gateway in the infrastructure
- [ ] I know how to configure the Gateway locally
- [ ] I can explain the OAuth2 flow: login → cookies → API calls
- [ ] I know how to add a new protected route
- [ ] I understand the refresh token flow
- [ ] I know why we prevent header spoofing
- [ ] I can debug a JWT problem
- [ ] I know where to place environment variables
- [ ] I understand the 4 Spring profiles
- [ ] I can deploy the Gateway to production

If you can check all of these → You're ready!

---

**Welcome to the Gateway Service!**

Start with [README.md](../README.md) →
