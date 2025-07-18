package ru.beeline.fdmgateway.filter;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import ru.beeline.fdmgateway.client.ProductClient;
import ru.beeline.fdmgateway.dto.ApiSecretDto;
import ru.beeline.fdmgateway.exception.*;
import ru.beeline.fdmgateway.service.UserService;
import ru.beeline.fdmgateway.utils.AuthUtils;
import ru.beeline.fdmgateway.utils.jwt.JwtUserData;
import ru.beeline.fdmgateway.utils.jwt.JwtUtils;
import ru.beeline.fdmlib.dto.auth.UserInfoDTO;

import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static ru.beeline.fdmgateway.utils.Constants.*;
import static ru.beeline.fdmgateway.utils.jwt.JwtUtils.getUserData;


@Slf4j
@Component
public class ValidateTokenFilter implements WebFilter {
    private static final Set<String> EXCLUDED_PATHS = Set.of(
            "/api-docs",
            "/favicon.ico",
            "/swagger",
            "/openapi.json",
            "/.well-known",
            "/actuator/prometheus",
            "/cache",
            "/api-gateway/capability/v2/tech/",
            "/eauthkey"
    );

    @Autowired
    private Environment environment;
    private final UserService userService;
    private final ProductClient productClient;
    private final AuthUtils authUtils;


    public ValidateTokenFilter(UserService userService, ProductClient productClient, AuthUtils authUtils) {
        this.userService = userService;
        this.productClient = productClient;
        this.authUtils = authUtils;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String requestId = exchange.getRequest().getId();

        for (String excludedPath : EXCLUDED_PATHS) {
            if (exchange.getRequest().getPath().toString().contains(excludedPath)) {
                return chain.filter(exchange);
            }
        }

        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (token == null) {
            token = exchange.getRequest().getHeaders().getFirst("X-Authorization");
            try {
                validateXAuthorizationToken(exchange);
            } catch (UnauthorizedException e) {
                log.error(e.getMessage());
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            } catch (BadRequestException e) {
                log.error(e.getMessage());
                exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
                return exchange.getResponse().setComplete();
            } catch (ServerErrorException e) {
                log.error(e.getMessage());
                exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
                return exchange.getResponse().setComplete();
            }
        }

        log.info(requestId + " DEBUG: Try validateToken");
        try {
            if (Arrays.stream(environment.getActiveProfiles()).noneMatch(
                    env -> (env.equalsIgnoreCase("local")) || (env.equalsIgnoreCase("func")) || (env.equalsIgnoreCase("e2e")))) {
                validate(token, requestId);
            }
        } catch (Exception e) {
            log.error(e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        JwtUserData tokenData = getUserData(token);
        log.info(requestId + "DEBUG: token is:" + tokenData.toString());
        UserInfoDTO userInfo = userService.getUserInfo(tokenData.getEmail(), tokenData.getFullName(), tokenData.getEmployeeNumber());
        if (userInfo != null) {
            log.info(requestId + " DEBUG: userInfo First: " + "getId:" + userInfo.getId().toString());
            log.info(requestId + " DEBUG: userInfo: " + "getProductsIds:" + userInfo.getProductsIds().stream().map(Objects::toString).collect(Collectors.toList()).toString());
            log.info(requestId + " DEBUG: userInfo: " + "getRoles:" + userInfo.getRoles().stream().map(Objects::toString).collect(Collectors.toList()).toString());
            log.info(requestId + " DEBUG: userInfo: " + "getPermissions:" + userInfo.getPermissions().stream().map(Objects::toString).collect(Collectors.toList()).toString());
            ServerHttpRequest request = exchange.getRequest()
                    .mutate()
                    .header(USER_ID_HEADER, userInfo.getId().toString())
                    .header(USER_PRODUCTS_IDS_HEADER, userInfo.getProductsIds().stream().map(Objects::toString).collect(Collectors.toList()).toString())
                    .header(USER_ROLES_HEADER, userInfo.getRoles().stream().map(Objects::toString).collect(Collectors.toList()).toString())
                    .header(USER_PERMISSION_HEADER, userInfo.getPermissions().stream().map(Objects::toString).collect(Collectors.toList()).toString())
                    .build();

            exchange = exchange.mutate().request(request).build();
        }
        String currentPath = exchange.getRequest().getPath().toString();
        if (currentPath.matches(".*user/[^/]+/info.*")) {
            exchange.getResponse().setStatusCode(HttpStatus.OK);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

            ObjectMapper objectMapper = new ObjectMapper();
            DataBufferFactory dataBufferFactory = exchange.getResponse().bufferFactory();
            try {
                DataBuffer dataBuffer = dataBufferFactory.wrap(objectMapper.writeValueAsBytes(userInfo));
                return exchange.getResponse().writeWith(Mono.just(dataBuffer));
            } catch (JsonProcessingException e) {
                log.error("Error processing JSON");
                exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                return exchange.getResponse().setComplete();
            }
        }

        return chain.filter(exchange);
    }

    private void validateXAuthorizationToken(ServerWebExchange exchange) {
        String token = exchange.getRequest().getHeaders().getFirst("X-Authorization");

        if (token == null || token.trim().isEmpty()) {
            throw new UnauthorizedException("Invalid X-Authorization token");
        }

        String[] parts = token.split(":");

        if (parts.length != 2) {
            throw new UnauthorizedException("Invalid X-Authorization token");
        }

        String apiKey = parts[0];
        String base64String = parts[1];

        if (apiKey == null || apiKey.isEmpty() || base64String == null || base64String.isEmpty()) {
            throw new UnauthorizedException("Invalid X-Authorization token");
        }

        try {
            byte[] decodedBytes = java.util.Base64.getDecoder().decode(base64String);
        } catch (IllegalArgumentException e) {
            throw new UnauthorizedException("Invalid X-Authorization token");
        }

        String nonceHeader = exchange.getRequest().getHeaders().getFirst("Nonce");
        if (nonceHeader == null || nonceHeader.trim().isEmpty()) {
            throw new BadRequestException("Invalid nonce header");
        }
        Boolean serviceAuth = Boolean.valueOf(exchange.getRequest().getHeaders().getFirst("Service-Auth"));
        ApiSecretDto apiSecretDto = serviceAuth ? productClient.getServiceKey(apiKey) : productClient.getProductKey(apiKey);
        boolean isValid = false;
        try {
            String message = authUtils.buildMessage(exchange.getRequest().getMethod().name(),
                    exchange.getRequest().getPath().value(),
                    exchange.getRequest().getBody().toString(),
                    exchange.getRequest().getHeaders().getFirst("Content-Type")
                    , nonceHeader);
            isValid = AuthUtils.validateAuthorization(message, apiSecretDto.getApiSecret(), base64String);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        if (isValid) {
            throw new UnauthorizedException("Invalid X-Authorization token");
        }

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
}
