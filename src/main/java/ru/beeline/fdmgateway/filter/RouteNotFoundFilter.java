/*
 * Copyright (c) 2025 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.HandlerMapping;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Отсекает запросы, для которых нет ни маршрута в spring.cloud.gateway.routes,
 * ни собственного контроллера гейтвея, ДО того как запрос попадёт в ValidateTokenFilter.
 * Иначе ValidateTokenFilter успевает сходить в fdm-auth за авторизацией, там для
 * неизвестного пути тоже нет записи в user_auth.route, и он возвращает 403
 * "Нет прав доступа" раньше, чем до маршрута вообще доходит очередь.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RouteNotFoundFilter implements WebFilter {

    private final List<HandlerMapping> handlerMappings;
    private final ObjectMapper objectMapper;

    public RouteNotFoundFilter(List<HandlerMapping> handlerMappings, ObjectMapper objectMapper) {
        this.handlerMappings = handlerMappings;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return Flux.fromIterable(handlerMappings)
                .flatMap(mapping -> recognizesPath(mapping, exchange))
                .any(Boolean::booleanValue)
                .flatMap(matched -> matched ? chain.filter(exchange) : writeNotRoutedResponse(exchange));
    }

    /**
     * true, если mapping вернул хендлер ИЛИ упал ошибкой (например, MethodNotAllowedException —
     * путь известен, просто не тот метод: это не "путь не найден", а отдельная ошибка,
     * которую должен вернуть обычный dispatch). false — только если путь совсем не распознан.
     */
    private Mono<Boolean> recognizesPath(HandlerMapping mapping, ServerWebExchange exchange) {
        return mapping.getHandler(exchange)
                .map(handler -> Boolean.TRUE)
                .onErrorReturn(Boolean.TRUE)
                .defaultIfEmpty(Boolean.FALSE);
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
