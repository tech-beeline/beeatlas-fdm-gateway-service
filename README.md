# FDM Gateway

API Gateway для экосистемы FDM. Даёт **единую точку входа** к микросервисам, проксирует запросы по маршрутам Spring Cloud Gateway, умеет проверять авторизацию и собирать единый Swagger.

## Что делает сервис

- **Роутинг**: входящие запросы на `/api-gateway/...` проксируются в нужный backend (правила в `src/main/resources/application.yml`).
- **Авторизация**:
  - **`Authorization: Bearer <JWT>`** — пользовательские запросы.
  - **`X-Authorization` (HMAC)** — сервис-сервис (API key + HMAC подпись, + `Nonce`).
- **Инжект пользователя**: из JWT берутся поля (`email`, `given_name`, `family_name`, `Employee-Number`), затем gateway обращается в auth-сервис и добавляет в запрос заголовки:
  - `user-id`, `user-roles`, `user-permission`, `user-products-ids`.
- **Кэш пользователя**: кэшируется `UserInfoDTO` с TTL (`spring.cache.expiration`).

## Быстрый старт

### Локально (Maven/IDE)

Требования: **Java 17**, Maven.

```bash
mvn -q clean package
java -jar target/*.jar --spring.profiles.active=local
```

Полезно для отладки:
- профиль **`local`** отключает крипто-проверку подписи/срока JWT в фильтре (но формат JWT всё равно должен быть корректным).

### Docker / Podman Compose (полный стенд)

В репозитории есть несколько compose-файлов:
- **`infrastructure/docker-compose.yml`** — стенд с БД/очередью/redis/authentik и т.п. (для локальной разработки).
- **`docker-compose.yml`** — минимальный compose (authentik + gateway) в корне.

Запуск стенда:

```bash
cd infrastructure
podman compose up --build
```

Остановка:

```bash
podman compose down
```

## Проверка работоспособности

- **Gateway welcome**: `GET http://localhost:8080/`
- **Swagger UI**: `http://localhost:8080/swagger-ui.html` — единый UI со списком сервисов (dropdown)

## Как добавить новый сервис в Swagger gateway

Единый Swagger UI собирает спеки бэкендов через `springdoc.swagger-ui.urls`. Чтобы сервис появился в dropdown и «Try it out» ходил через gateway, правки делаются в `src/main/resources/application.yml` и в `OpenApiServerPrefixResolver`.

Ориентир — уже подключённые сервисы вроде Products / Graph / Document (`path.*2` + route `*2` + запись в `urls`).

### 1. Путь в `path:` (`application.yml`)

Добавьте префикс, по которому gateway будет отдавать OpenAPI-спеку наружу (обычно короткий путь без `/api-gateway`):

```yaml
path:
  # ...
  myservice2: /myservice
```

И URL бэкенда в `integration.*` (если его ещё нет) — его же использует route.

### 2. Запись в Swagger UI (`springdoc.swagger-ui.urls`)

В том же `application.yml`:

```yaml
springdoc:
  swagger-ui:
    urls:
      # ...
      - name: My Service
        url: ${path.myservice2}/v3/api-docs
```

`url` — путь **через gateway**, не прямой URL сервиса. Типичные варианты спеки:

| Тип бэкенда | Пример `url` |
|-------------|--------------|
| SpringDoc / OpenAPI 3 | `${path.xxx2}/v3/api-docs` |
| FastAPI и т.п. | `${path.xxx2}/openapi.json` |
| Старый Swagger 2 | `${path.xxx2}/swagger-ui/summary/swagger.json` |

### 3. Route, который проксирует спеку и API

Нужен маршрут, который отдаёт `api-docs` (и обычно всё API) с префикса `path.myservice2` на бэкенд:

```yaml
spring.cloud.gateway.routes:
  - id: myService2
    uri: ${integration.myservice-server-url}
    predicates:
      - Path=${path.myservice2}/**
    filters:
      - RewritePath=${path.myservice2}/(?<segment>.*), /$\{segment}
```

Так запрос `GET /myservice/v3/api-docs` уходит в сервис как `GET /v3/api-docs`.

### 4. Префикс для «Try it out» (`OpenApiServerPrefixResolver`)

Gateway переписывает `servers` в скачанной спеке, чтобы кнопки Swagger ходили через gateway, а не напрямую в сервис.

В файле `config/OpenApiServerPrefixResolver.java` в конструктор добавьте параметр и вызов `add` по аналогии с соседними сервисами:

1. параметр: `@Value("${path.myservice2}") String myservice2`
2. в теле: `add(list, myservice2, myservice2);`

Без этого спека в UI появится, но вызовы из Swagger могут уходить не туда.

### Чеклист

1. `path.myservice2` (+ `integration.*`, если нужно)
2. пункт в `springdoc.swagger-ui.urls`
3. gateway route на `${path.myservice2}/**`
4. запись в `OpenApiServerPrefixResolver`
5. у самого сервиса должен быть доступен OpenAPI (`/v3/api-docs` или аналог)
6. перезапуск gateway → в Swagger UI выбрать сервис в dropdown

> Маршруты «боевого» API (`/api-gateway/...`) и swagger-маршрут (`/myservice/...`) часто разделены: первый — для клиентов, второй — для агрегации документации. Для появления в Swagger UI достаточно второго контура (`*2` + `urls` + resolver).

### Проверочный запрос на прохождение авторизации (через gateway)

Удобный “тестовый” путь, который обрабатывается прямо в фильтре:

```bash
curl -v "http://localhost:8080/api-gateway/auth/v1/user/1/info" \
  -H "Authorization: Bearer <JWT>"
```

Важно: даже на профиле `local` gateway после чтения JWT идёт в auth-сервис (`INTEGRATION_AUTH_SERVER_URL`). Если auth-сервис не поднят/недоступен по DNS в сети compose — будут ошибки.

## Важные переменные окружения

Gateway читает URL интеграций из env (см. `docker-compose.yml` / `infrastructure/docker-compose.yml`):

- **`INTEGRATION_AUTH_SERVER_URL`**: адрес auth-сервиса (где профили/права).
- **`JWKS`**: URL до JWKS (публичный ключ для проверки RSA JWT), если используется режим загрузки ключа по URL.
- **`SPRING_PROFILES_ACTIVE`**: активный профиль (`local` / `func` / `e2e` / и т.д.).

## Authentik (OIDC) — минимальная настройка

Если вы используете Authentik как IdP:

1. Откройте админку Authentik: `http://localhost:5000`
2. Создайте **OAuth2/OpenID Provider** (OIDC).
3. Получите JWKS эндпоинт вида:
  - `http://authentik-server:9000/application/o/<slug>/jwks/` (внутри compose)
  - `http://localhost:5000/application/o/<slug>/jwks/` (с хоста)
4. Убедитесь, что gateway берёт ключ именно оттуда (через `JWKS` или через настройки режима authentic-auth, если он включён в конфиге).

## Типовые проблемы и решения

- **`statfs ... data/media: no such file or directory` при старте Authentik**  
  В compose используются bind-mount’ы на папки `./data/...`. Создайте их заранее или переключитесь на именованные тома.

- **`PostgreSQL connection failed ... Name or service not known` в Authentik**  
  Это DNS/сеть: контейнер не может резолвнуть хост БД. Проверьте:
  - что `AUTHENTIK_POSTGRESQL__HOST` равен имени сервиса БД в compose (например, `authentik-postgres`);
  - что оба сервиса в одной сети (`fdm-network`);
  - что вы запускаете сервисы одной командой `podman compose up`, а не отдельно.

- **Gateway отдаёт 500 / NPE при запросе с JWT**  
  Обычно это недоступный auth-сервис (`UnknownHostException` на `fdm-auth-backend...`). Исправьте `INTEGRATION_AUTH_SERVER_URL` и/или поднимите auth-сервис в той же сети.

## Структура проекта

```
src/main/java/ru/beeline/fdmgateway/
├── client/        # HTTP-клиенты к backend-сервисам
├── controller/    # собственные эндпоинты gateway (welcome, cache, и т.п.)
├── filter/        # фильтры (ValidateTokenFilter и др.)
├── service/       # логика кэша пользователя, интеграции
└── utils/         # JWT/JWKS/E-Auth/HMAC утилиты
```
