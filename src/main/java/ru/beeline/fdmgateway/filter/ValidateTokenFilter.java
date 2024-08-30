package ru.beeline.fdmgateway.filter;

import com.auth0.jwt.exceptions.JWTDecodeException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import ru.beeline.fdmgateway.exception.InvalidTokenException;
import ru.beeline.fdmgateway.exception.TokenExpiredException;
import ru.beeline.fdmgateway.service.UserService;
import ru.beeline.fdmgateway.utils.jwt.JwtUserData;
import ru.beeline.fdmgateway.utils.jwt.JwtUtils;
import ru.beeline.fdmlib.dto.auth.UserInfoDTO;

import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static ru.beeline.fdmgateway.utils.Constants.USER_ID_HEADER;
import static ru.beeline.fdmgateway.utils.Constants.USER_PERMISSION_HEADER;
import static ru.beeline.fdmgateway.utils.Constants.USER_PRODUCTS_IDS_HEADER;
import static ru.beeline.fdmgateway.utils.Constants.USER_ROLES_HEADER;
import static ru.beeline.fdmgateway.utils.jwt.JwtUtils.getUserData;


@Slf4j
@Component
public class ValidateTokenFilter implements WebFilter {
    private static final Set<String> EXCLUDED_PATHS = Set.of(
            "/swagger",
            "/cache",
            "/api-gateway/capability/v2/tech/",
            "/api-docs",
            "/actuator/prometheus",
            "/eauthkey"
    );

    @Autowired
    private Environment environment;
    private final UserService userService;

    public ValidateTokenFilter(UserService userService) {
        this.userService = userService;
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
        log.info(requestId + " DEBUG: Try validateToken");
        try {
            if (Arrays.stream(environment.getActiveProfiles()).noneMatch(
                    env -> (env.equalsIgnoreCase("func")))) {
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
        return chain.filter(exchange);
    }

    private void validate(String bearerToken, String requestId) throws InvalidTokenException, TokenExpiredException {
        if (bearerToken == null || bearerToken.trim().isEmpty() ||
                !JwtUtils.isValid(bearerToken)) {
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
