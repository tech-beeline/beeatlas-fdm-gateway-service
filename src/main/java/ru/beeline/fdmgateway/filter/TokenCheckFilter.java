package ru.beeline.fdmgateway.filter;

import com.auth0.jwt.exceptions.JWTDecodeException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import ru.beeline.fdmgateway.exception.InvalidTokenException;
import ru.beeline.fdmgateway.exception.TokenExpiredException;
import ru.beeline.fdmgateway.utils.jwt.JwtUserData;
import ru.beeline.fdmgateway.utils.jwt.JwtUtils;

import java.util.Collections;

@Slf4j
@Component
public class TokenCheckFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        try {
            validate(exchange.getRequest().getHeaders().getFirst("Authorization"));

        } catch (Exception e) {
            log.error(e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Продолжить выполнение маршрутизации
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
