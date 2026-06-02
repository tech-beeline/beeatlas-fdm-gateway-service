/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.filter;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import ru.beeline.fdmgateway.client.ProductClient;
import ru.beeline.fdmgateway.dto.ApiSecretDto;
import ru.beeline.fdmgateway.dto.AuthorizeResponseDTO;
import ru.beeline.fdmgateway.dto.UserInfoDTO;
import ru.beeline.fdmgateway.exception.InvalidTokenException;
import ru.beeline.fdmgateway.exception.TokenExpiredException;
import ru.beeline.fdmgateway.service.AuthorizeService;
import ru.beeline.fdmgateway.utils.AuthUtils;
import ru.beeline.fdmgateway.utils.jwt.JwtUserData;
import ru.beeline.fdmgateway.utils.jwt.JwtUtils;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static ru.beeline.fdmgateway.dto.PermissionTypeDTO.DESIGN_ARTIFACT;
import static ru.beeline.fdmgateway.utils.Constants.*;
import static ru.beeline.fdmgateway.utils.jwt.JwtUtils.getUserData;


@Slf4j
@Component
public class ValidateTokenFilter implements WebFilter {

    private static final String MCP_TOKEN_HEADER = "MCP-Authorization";
    private static final Set<String> EXCLUDED_PATHS = Set.of(
            "/api-docs",
            "/favicon.ico",
            "/swagger",
            "/openapi.json",
            "/.well-known",
            "/actuator/prometheus",
            "/actuator/health",
            "/cache",
            "/api-gateway/capability/v2/tech/",
            "/eauthkey"
    );
    private static final Set<String> BLACK_LIST_PATHS = Set.of(
            "api/v1/service"
    );

    @Autowired
    private Environment environment;
    private final AuthorizeService authorizeService;
    private final ProductClient productClient;
    private final AuthUtils authUtils;
    private final Boolean demoAuth;
    private final String mcpTokens;

    public ValidateTokenFilter(AuthorizeService authorizeService,
                               ProductClient productClient, AuthUtils authUtils,
                               @Value("${app.demo-auth}") Boolean demoAuth,
                               @Value("${app.mcp-token:}") String mcpTokens) {
        this.authorizeService = authorizeService;
        this.productClient = productClient;
        this.authUtils = authUtils;
        this.demoAuth = demoAuth;
        this.mcpTokens = mcpTokens;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
            log.debug("OPTIONS request");
            return chain.filter(exchange);
        }
        for (String path : BLACK_LIST_PATHS) {
            if (exchange.getRequest().getPath().toString().contains(path)) {
                log.info("path = " + exchange.getRequest().getPath().toString() + " в блэк листе");
                return writeErrorResponse(exchange, HttpStatus.NOT_FOUND, "Server not found");
            }
        }
        for (String excludedPath : EXCLUDED_PATHS) {
            if (exchange.getRequest().getPath().toString().contains(excludedPath)) {
                return chain.filter(exchange);
            }
        }
        String auth = exchange.getRequest().getHeaders().getFirst("Authorization");
        String xAuth = exchange.getRequest().getHeaders().getFirst("X-Authorization");
        String mcpHeaderToken = exchange.getRequest().getHeaders().getFirst(MCP_TOKEN_HEADER);

        if (isMcpAuthorized(mcpHeaderToken) && !demoAuth) {
            log.info("MCP запрос");
            JwtUserData tokenData = new JwtUserData(new HashMap<>());
            tokenData.setEmail("mcp@default.local");
            tokenData.setName("MCP");
            tokenData.setLastName("Assistant");
            tokenData.setEmployeeNumber("mcp");
            tokenData.setWinAccountName("mcp");
            tokenData.setSub("mcp");
            return injectUserAndContinue(exchange, tokenData, chain, exchange.getRequest().getId(), true, null);
        }
        if ((auth != null && !auth.isEmpty()) && (xAuth != null && !xAuth.isEmpty())) {
            return writeErrorResponse(exchange, HttpStatus.BAD_REQUEST, "Only one authorization header allowed");
        }
        if(!demoAuth) {
            if ((auth == null || auth.isEmpty()) && (xAuth == null || xAuth.isEmpty())) {
                return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Missing authorization header");
            }
        }
        if (auth != null && !auth.isEmpty() && !demoAuth) {
            try {
                if (Arrays.stream(environment.getActiveProfiles())
                        .noneMatch(env -> env.equalsIgnoreCase("local") || env.equalsIgnoreCase("func") || env.equalsIgnoreCase("e2e"))) {
                    validate(auth, exchange.getRequest().getId());
                }
            } catch (Exception e) {
                log.error(e.getMessage());
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
            JwtUserData tokenData = getUserData(auth);
            String requestId = exchange.getRequest().getId();
            return readAndCacheBody(exchange).flatMap(pair ->
                    injectUserAndContinue(pair.getKey(), tokenData, chain, requestId, false, pair.getValue()));
        } else if (demoAuth) {
            JwtUserData tokenData = new JwtUserData(new HashMap<>());
            String requestId = exchange.getRequest().getId();
            return readAndCacheBody(exchange).flatMap(pair ->
                    injectUserAndContinue(pair.getKey(), tokenData, chain, requestId, false, pair.getValue()));
        } else {
            return validateXAuthorizationToken(exchange)
                    .flatMap(mutatedExchange -> {
                        String token = mutatedExchange.getRequest().getHeaders().getFirst("X-Authorization");
                        JwtUserData tokenData = createDefaultUserDataFromXAuth(token);
                        return injectUserAndContinue(mutatedExchange, tokenData, chain, exchange.getRequest().getId(), true, null);
                    });
        }
    }

    private boolean isMcpAuthorized(String providedToken) {
        if (providedToken == null || providedToken.isBlank()) return false;
        if (mcpTokens == null || mcpTokens.isBlank()) return false;
        return Arrays.stream(mcpTokens.split(","))
                .map(String::trim)
                .anyMatch(validToken -> validToken.equals(providedToken));
    }

    private JwtUserData createDefaultUserDataFromXAuth(String xAuth) {
        log.info("Создание дефолтного юзера");
        String apiKey = extractApiKeyFromXAuth(xAuth);
        JwtUserData userData = new JwtUserData(new HashMap<>());
        userData.setEmail(apiKey + "@default.local");
        userData.setName("XAuthUser");
        userData.setLastName(apiKey);
        userData.setEmployeeNumber(apiKey);
        userData.setWinAccountName(apiKey);
        userData.setSub(apiKey);
        log.info(">>>>>>>>>>>UserData: " + userData);
        return userData;
    }

    private String extractApiKeyFromXAuth(String xAuth) {
        if (xAuth == null) return null;
        int colonPos = xAuth.indexOf(":");
        if (colonPos == -1) return null;
        return xAuth.substring(0, colonPos);
    }

    public UserInfoDTO buildDefaultUser() {
        UserInfoDTO user = new UserInfoDTO();
        user.setId(0);
        user.setRoles(List.of("ADMINISTRATOR"));
        user.setProductsIds(List.of());
        user.setPermissions(List.of(DESIGN_ARTIFACT));
        log.info(">>>>>>>>>>>>>>>UserInfoDTO: " + user);
        return user;
    }

    private Mono<Void> injectUserAndContinue(ServerWebExchange exchange, JwtUserData tokenData,
                                              WebFilterChain chain, String requestId,
                                              Boolean isXAuth, String bodyJson) {
        if (demoAuth) {
            tokenData.setEmail("default@beeline.ru");
            tokenData.setLastName("Ivan");
            tokenData.setName("Ivanov");
            tokenData.setEmployeeNumber("1");
        }
        if (isXAuth) {
            return continueWithUserInfo(exchange, buildDefaultUser(), chain, requestId);
        }
        final ServerWebExchange finalExchange = exchange;
        return Mono.fromCallable(() -> Optional.ofNullable(authorizeService.authorize(
                        tokenData,
                        finalExchange.getRequest().getMethod().name(),
                        finalExchange.getRequest().getPath().toString(),
                        finalExchange.getRequest().getQueryParams().toSingleValueMap(),
                        bodyJson)))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(opt -> {
                    if (opt.isEmpty()) {
                        return writeErrorResponse(finalExchange, HttpStatus.SERVICE_UNAVAILABLE, "Authorization service unavailable");
                    }
                    AuthorizeResponseDTO authResponse = opt.get();
                    if (!"ALLOW".equals(authResponse.getDecision())) {
                        return writeErrorResponse(finalExchange, HttpStatus.FORBIDDEN, "Forbidden");
                    }
                    return continueWithUserInfo(finalExchange, authorizeService.toUserInfo(authResponse), chain, requestId);
                });
    }

    private Mono<Void> continueWithUserInfo(ServerWebExchange exchange, UserInfoDTO userInfo,
                                             WebFilterChain chain, String requestId) {
        log.info(requestId + " DEBUG: userInfo First: " + "getId:" + userInfo.getId().toString());
        ServerHttpRequest request = exchange.getRequest()
                .mutate()
                .header(USER_ID_HEADER, userInfo.getId().toString())
                //.header(USER_PRODUCTS_IDS_HEADER, userInfo.getProductsIds().toString())
                .header(USER_ROLES_HEADER, userInfo.getRoles() != null ? userInfo.getRoles().toString() : "[]")
                //.header(USER_PERMISSION_HEADER, userInfo.getPermissions().toString())
                .headers(headers -> headers.remove("authorization"))
                .build();
        ServerWebExchange mutated = exchange.mutate().request(request).build();

        String currentPath = mutated.getRequest().getPath().toString();
        if (currentPath.matches(".*user/[^/]+/info.*")) {
            mutated.getResponse().setStatusCode(HttpStatus.OK);
            mutated.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
            try {
                byte[] bytes = new ObjectMapper().writeValueAsBytes(userInfo);
                DataBuffer buffer = mutated.getResponse().bufferFactory().wrap(bytes);
                return mutated.getResponse().writeWith(Mono.just(buffer));
            } catch (JsonProcessingException e) {
                log.error("Error processing JSON", e);
                mutated.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                return mutated.getResponse().setComplete();
            }
        }
        return chain.filter(mutated);
    }

    private Mono<ServerWebExchange> validateXAuthorizationToken(ServerWebExchange exchange) {
        String token = exchange.getRequest().getHeaders().getFirst("X-Authorization");
        if (token == null || token.trim().isEmpty()) {
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid X-Authorization token")
                    .then(Mono.empty());
        }
        String[] parts = token.split(":");
        if (parts.length != 2) {
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid X-Authorization token format")
                    .then(Mono.empty());
        }
        String apiKey = parts[0];
        String base64String = parts[1];

        if (apiKey.isEmpty() || base64String.isEmpty()) {
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid X-Authorization token parts")
                    .then(Mono.empty());
        }
        String nonceHeader = exchange.getRequest().getHeaders().getFirst("Nonce");
        if (nonceHeader == null || nonceHeader.trim().isEmpty()) {
            return writeErrorResponse(exchange, HttpStatus.BAD_REQUEST, "Missing or invalid Nonce header")
                    .then(Mono.empty());
        }
        ApiSecretDto apiSecretDto;
        try {
            Boolean serviceAuth = Boolean.valueOf(exchange.getRequest().getHeaders().getFirst("Service-Auth"));
            apiSecretDto = serviceAuth ? productClient.getServiceKey(apiKey) : productClient.getProductKey(apiKey);
        } catch (Exception e) {
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Not authorized. Error fetching API secret")
                    .then(Mono.empty());
        }
        String contentType = Optional.ofNullable(exchange.getRequest().getHeaders().getFirst("Content-Type")).orElse("");
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .defaultIfEmpty(exchange.getResponse().bufferFactory().wrap(new byte[0]))
                .flatMap(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    String requestBody = new String(bytes, StandardCharsets.UTF_8);
                    String message;
                    try {
                        message = authUtils.buildMessage(
                                exchange.getRequest().getMethod().name(),
                                exchange.getRequest().getPath().value(),
                                requestBody,
                                contentType,
                                nonceHeader
                        );
                    } catch (NoSuchAlgorithmException e) {
                        return writeErrorResponse(exchange, HttpStatus.INTERNAL_SERVER_ERROR, "Error building message")
                                .then(Mono.empty());
                    }
                    if (apiSecretDto.getApiSecret() == null || apiSecretDto.getApiSecret().isEmpty()) {
                        return writeErrorResponse(exchange, HttpStatus.NOT_FOUND, "apiSecret is empty")
                                .then(Mono.empty());
                    }
                    boolean isValid = AuthUtils.validateAuthorization(message, apiSecretDto.getApiSecret(), base64String);
                    if (!isValid) {
                        return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Invalid X-Authorization token signature")
                                .then(Mono.empty());
                    }
                    Flux<DataBuffer> cachedFlux = Flux.defer(() -> {
                        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
                        return Mono.just(buffer);
                    });
                    ServerHttpRequest mutatedRequest = new ServerHttpRequestDecorator(exchange.getRequest()) {
                        @Override
                        public Flux<DataBuffer> getBody() {
                            return cachedFlux;
                        }
                    };
                    ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();
                    return Mono.just(mutatedExchange);
                });
    }

    private void validate(String bearerToken, String requestId) throws InvalidTokenException, TokenExpiredException {
        if (!JwtUtils.isValid(bearerToken)) {
            log.info(requestId + " DEBUG: Invalid token");
            throw new InvalidTokenException("Invalid token");
        } else {
            try {
                if (JwtUtils.isExpired(bearerToken)) {
                    log.info(requestId + " DEBUG: Bearer token is expired");
                    throw new TokenExpiredException("Bearer token is expired");
                }
            } catch (JWTDecodeException e) {
                log.error(e.getMessage());
                log.info(requestId + " DEBUG: Something with token: " + e.getMessage());
                throw new InvalidTokenException("Invalid token");
            }
        }
    }

    private Mono<java.util.AbstractMap.SimpleEntry<ServerWebExchange, String>> readAndCacheBody(ServerWebExchange exchange) {
        HttpMethod method = exchange.getRequest().getMethod();
        if (method == HttpMethod.GET || method == HttpMethod.DELETE || method == HttpMethod.HEAD) {
            return Mono.just(new java.util.AbstractMap.SimpleEntry<>(exchange, (String) null));
        }
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .defaultIfEmpty(exchange.getResponse().bufferFactory().wrap(new byte[0]))
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    String bodyJson = bytes.length > 0 ? new String(bytes, StandardCharsets.UTF_8) : null;
                    Flux<DataBuffer> cachedBody = Flux.defer(() ->
                            Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
                    ServerHttpRequest mutated = new ServerHttpRequestDecorator(exchange.getRequest()) {
                        @Override
                        public Flux<DataBuffer> getBody() { return cachedBody; }
                    };
                    return new java.util.AbstractMap.SimpleEntry<>(
                            exchange.mutate().request(mutated).build(), bodyJson);
                });
    }

    private Mono<Void> writeErrorResponse(ServerWebExchange exchange, HttpStatus status, String message) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String body = String.format("{\"message\": \"%s\"}", message);
        DataBuffer buffer = exchange.getResponse()
                .bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
