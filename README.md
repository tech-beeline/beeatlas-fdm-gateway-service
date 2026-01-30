# FDM Gateway

API gateway for the FDM (Federated Data Management) ecosystem, providing a single entry point to FDM microservices. Handles request routing, authentication (JWT and X-Authorization), and aggregation of OpenAPI documentation.

## Technologies

- **Java 17**
- **Spring Boot 2.7.3**
- **Spring Cloud Gateway** — routing and proxying
- **Spring WebFlux** — reactive stack
- **JWT** (jjwt, java-jwt) — Bearer token validation
- **SpringDoc OpenAPI** — unified Swagger UI for all services
- **OpenTelemetry** — tracing and metrics
- **Micrometer + Prometheus** — metrics for monitoring
- **fdm-lib** — internal FDM library

## Features

- **Single entry point** — all requests to backends go through the gateway at paths like `/api-gateway/<service>/v1/...`
- **Two authentication types:**
  - **Authorization (Bearer JWT)** — for users; signature and expiry validation, user data injection from Auth service
  - **X-Authorization** — for services (API Key + request signature); supports Product Key and Service Key
- **User caching** — user data is cached with configurable TTL; cache management via `DELETE /cache` and `DELETE /cache/{login}`
- **E-Auth public key** — endpoint `/api/runtime/v1/eauthkey` to retrieve the key
- **Path blacklist** — block unwanted routes
- **Token validation exemptions** — e.g. Swagger, actuator, prometheus, eauthkey

## Routed services

| Service       | Base path                      | Purpose                          |
|---------------|--------------------------------|----------------------------------|
| CX            | `/api-gateway/cx/...`          | Business interactions, CJ, BPMN  |
| Auth          | `/api-gateway/auth/v1`         | Users and admin                  |
| Products      | `/api-gateway/product/v1`      | Products, fitness functions      |
| Techradar     | `/api-gateway/techradar/v1`    | Tech radar                       |
| Capability    | `/api-gateway/capability/v1`   | Business/tech capabilities        |
| Dashboard     | `/api-gateway/capability/v2`   | Dashboard                        |
| Notification  | `/api-gateway/notify/v1`       | Notifications                    |
| Document      | `/api-gateway/document/v1`     | Documents                        |
| BPM (Camunda) | `/api-gateway/camunda-process/v1` | Processes and applications    |
| Pack Loader   | `/api-gateway/pack-loader/v1`  | Packages                         |
| Structurizr   | `/api-gateway/structurizr/v1`  | Architecture workspaces          |
| Graph         | `/api-gateway/graph/v1`        | Graph                            |

Exact paths and rewrites are defined in `application.yml` (sections `spring.cloud.gateway.routes` and `path`).

## Build and run

### Local (Maven)

```bash
mvn clean package
java -jar target/fdm-gateway-1.3.4.jar
```

Required environment variables (or Spring profiles) include:

- `integration.*-server-url` — backend service URLs (auth, products, cx, techradar, etc.)
- `path.*` — override base paths if needed
- `authentic-auth-url` — for authentic-auth mode
- `otel-exporter-otlp-endpoint` — for OpenTelemetry (when SDK is enabled)

### Docker

The image is built via GitLab CI (see `.gitlab-ci/Dockerfile`). Uses JRE 17, ports 8080, 8090, 10260.

## Configuration

- **`app.demo-auth`** — demo authentication mode (inject test user)
- **`app.authentic-auth`** — enable authentic-auth
- **`spring.cache.expiration`** — user cache TTL (ms)
- **`springdoc.swagger-ui.urls`** — OpenAPI list for Swagger UI (Gateway + all backends)

Routes and paths are defined in `src/main/resources/application.yml`; Helm values in `.gitlab-ci/helm/` are used for different environments (dev, e2e, func, prod).

## API Gateway (own endpoints)

| Method | Path                       | Description                          |
|--------|----------------------------|--------------------------------------|
| GET    | `/`                        | Welcome (app name and version)       |
| GET    | `/api/runtime/v1/eauthkey` | E-Auth public key                    |
| DELETE | `/cache`                   | Clear entire user cache              |
| DELETE | `/cache/{login}`           | Remove user from cache by login      |

All other requests are proxied to backends according to routing rules.

## API documentation

After startup, the unified Swagger UI is available at the default SpringDoc path (e.g. `/swagger-ui.html`). It includes specs for the Gateway and all listed backends (Products, Dashboard, BPMN, CX, Auth, Techradar, Capability, Notification, Document, Structurizr, Graph).

## Project structure

```
src/main/java/ru/beeline/fdmgateway/
├── FdmGatewayApplication.java   # Entry point, public key bean
├── client/                      # HTTP clients to backends (User, Product)
├── config/                      # OpenAPI and other configuration
├── controller/                  # Gateway endpoints (welcome, eauthkey, cache)
├── dto/                         # DTOs (ApiSecret, UserInfo, etc.)
├── exception/                   # Exceptions (InvalidToken, TokenExpired, Unauthorized, etc.)
├── filter/                      # ValidateTokenFilter, TraceIdResponseFilter
├── service/                     # UserService (user cache)
└── utils/                       # JWT, E-Auth, AuthUtils, RestHelper, constants
```

## License

Copyright (c) 2024 PJSC VimpelCom
