package ru.beeline.fdmgateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class CustomHeaderFilter implements GlobalFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            HttpHeaders headers = response.getHeaders();
            headers.compute("Access-Control-Allow-Headers", (key, existingValues) -> {
                if (existingValues == null) {
                    return List.of("Content-Type", "Authorization", "Content-Disposition");
                }
                Set<String> updatedValues = new HashSet<>(existingValues);
                updatedValues.add("Content-Disposition");
                return new ArrayList<>(updatedValues);
            });
        }));
    }
}
