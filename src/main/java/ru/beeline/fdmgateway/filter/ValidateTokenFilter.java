package ru.beeline.fdmgateway.filter;

import com.auth0.jwt.exceptions.JWTDecodeException;
import lombok.extern.slf4j.Slf4j;
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
import ru.beeline.fdmlib.dto.auth.*;


import java.util.Objects;
import java.util.stream.Collectors;

import static ru.beeline.fdmgateway.utils.jwt.JwtUtils.getUserData;


@Slf4j
@Component
public class ValidateTokenFilter implements WebFilter {
    private static final String USER_ID_HEADER = "user-id";
    private static final String USER_PERMISSION = "user-permission";
    private static final String USER_PRODUCTS_IDS_HEADER = "user-products-ids";
    private static final String USER_ROLES_HEADER = "user-roles";
    private final UserService userService;

    public ValidateTokenFilter(UserService userService) {
        this.userService = userService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (exchange.getRequest().getPath().toString().contains("swagger")
                || exchange.getRequest().getPath().toString().contains("/api-docs")
                || exchange.getRequest().getPath().toString().contains("/actuator/prometheus")
                || exchange.getRequest().getPath().toString().contains("/eauthkey")) {
            return chain.filter(exchange);
        }

        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
        try {
            validate(token);
        } catch (Exception e) {
            log.error(e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        JwtUserData tokenData = getUserData(token);
        log.info("token is:" + tokenData.toString());
        UserInfoDTO userInfo = userService.getUserInfo(tokenData.getEmail(), tokenData.getFullName(), tokenData.getEmployeeNumber());
        if (userInfo != null) {
            log.info("userInfo First: " + "getId:" + userInfo.getId().toString());
            log.info("userInfo: "  +"getProductsIds:" + userInfo.getProductsIds().stream().map(Objects::toString).collect(Collectors.toList()).toString());
            log.info("userInfo: "  + "getRoles:" + userInfo.getRoles().stream().map(Objects::toString).collect(Collectors.toList()).toString());
            log.info("userInfo: "  + "getPermissions:" + userInfo.getPermissions().stream().map(Objects::toString).collect(Collectors.toList()).toString());
            ServerHttpRequest request = exchange.getRequest()
                    .mutate()
                    .header(USER_ID_HEADER, userInfo.getId().toString())
                    .header(USER_PRODUCTS_IDS_HEADER, userInfo.getProductsIds().stream().map(Objects::toString).collect(Collectors.toList()).toString())
                    .header(USER_ROLES_HEADER, userInfo.getRoles().stream().map(Objects::toString).collect(Collectors.toList()).toString())
                    .header(USER_PERMISSION, userInfo.getPermissions().stream().map(Objects::toString).collect(Collectors.toList()).toString())
                    .build();

            exchange = exchange.mutate().request(request).build();
        }
        log.info("USER_ID_HEADER FIRST: " + USER_ID_HEADER +":" + exchange.getRequest().getHeaders().getFirst(USER_ID_HEADER));
        log.info("USER_ID_HEADER FIRST ALL: " + USER_ID_HEADER +":" + exchange.getRequest().getHeaders().get(USER_ID_HEADER));
        log.info("USER_PRODUCTS_IDS_HEADER: "  + USER_PRODUCTS_IDS_HEADER +":" + exchange.getRequest().getHeaders().getFirst(USER_PRODUCTS_IDS_HEADER));
        log.info("USER_ROLES_HEADER: "  + USER_ROLES_HEADER +":" + exchange.getRequest().getHeaders().getFirst(USER_ROLES_HEADER));
        log.info("USER_PERMISSION: "  + USER_PERMISSION +":" + exchange.getRequest().getHeaders().getFirst(USER_PERMISSION));

        return chain.filter(exchange);
    }


    private void validate(String bearerToken) throws InvalidTokenException, TokenExpiredException {
        if (bearerToken == null || bearerToken.trim().isEmpty() ||
                JwtUtils.isValid(bearerToken)) {
            throw new InvalidTokenException("Invalid token");
        } else {
            try {
                if (JwtUtils.isExpired(bearerToken)) {
                    throw new TokenExpiredException("Bearer token is expired");
                }
            } catch (JWTDecodeException e) {
                log.error(e.getMessage());
                throw new InvalidTokenException("Invalid token");
            }
        }
    }
}
