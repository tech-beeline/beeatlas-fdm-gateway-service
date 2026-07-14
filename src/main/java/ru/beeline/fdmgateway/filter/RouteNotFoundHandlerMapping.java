/*
 * Copyright (c) 2025 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.HandlerMapping;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebHandler;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
public class RouteNotFoundHandlerMapping implements HandlerMapping, Ordered {

    private final ObjectMapper objectMapper;

    public RouteNotFoundHandlerMapping(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }

    @Override
    public Mono<Object> getHandler(ServerWebExchange exchange) {
        WebHandler handler = this::writeNotRoutedResponse;
        return Mono.just(handler);
    }

    private Mono<Void> writeNotRoutedResponse(ServerWebExchange exchange) {
        String service = firstPathSegment(exchange.getRequest().getPath().value());
        String message = "На Gateway не существует маршрутизации на указанный сервис " + service;

        exchange.getResponse().setStatusCode(HttpStatus.NOT_IMPLEMENTED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(Map.of("errorMessage", message));
        } catch (Exception e) {
            bytes = "{\"errorMessage\": \"На Gateway не существует маршрутизации на указанный сервис\"}"
                    .getBytes(StandardCharsets.UTF_8);
        }
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    private String firstPathSegment(String path) {
        String trimmed = path.startsWith("/") ? path.substring(1) : path;
        int slashIndex = trimmed.indexOf('/');
        String segment = slashIndex >= 0 ? trimmed.substring(0, slashIndex) : trimmed;
        return "/" + segment;
    }
}
