package ru.beeline.fdmgateway.filter;

import com.auth0.jwt.exceptions.JWTDecodeException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import ru.beeline.fdmgateway.dto.UserInfo;
import ru.beeline.fdmgateway.exception.InvalidTokenException;
import ru.beeline.fdmgateway.exception.TokenExpiredException;
import ru.beeline.fdmgateway.service.UserService;
import ru.beeline.fdmgateway.utils.jwt.JwtUtils;

import java.util.Objects;
import java.util.stream.Collectors;

import static ru.beeline.fdmgateway.utils.jwt.JwtUtils.getUserData;


@Slf4j
@Component
public class ValidateTokenFilter implements WebFilter {
    private static final String USER_ID_HEADER = "USER_ID";
    private static final String USER_PERMISSION = "USER_PERMISSION";
    private static final String USER_PRODUCTS_IDS_HEADER = "USER_PRODUCTS_IDS";
    private static final String USER_ROLES_HEADER = "USER_ROLES";
    private final UserService userService;

    public ValidateTokenFilter(UserService userService) {
        this.userService = userService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
        try {
            validate(token);
        } catch (Exception e) {
            log.error(e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        UserInfo userInfo = userService.getUserInfo(Objects.requireNonNull(getUserData(token)).getName());
        if (userInfo != null) {
            exchange.getResponse().getHeaders().add(USER_ID_HEADER, userInfo.getId());
            exchange.getResponse().getHeaders().addAll(USER_PRODUCTS_IDS_HEADER, userInfo.getProductIds().stream().map(Objects::toString).collect(Collectors.toList()));
            exchange.getResponse().getHeaders().addAll(USER_ROLES_HEADER, userInfo.getRoles());
            exchange.getResponse().getHeaders().addAll(USER_PERMISSION, userInfo.getPermission());
        }
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
