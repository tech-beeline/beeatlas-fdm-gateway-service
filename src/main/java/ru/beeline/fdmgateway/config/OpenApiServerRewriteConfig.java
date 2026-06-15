/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.NettyWriteResponseFilter;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyResponseBodyGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Slf4j
@Configuration
public class OpenApiServerRewriteConfig {

    @Bean
    public GlobalFilter openApiServerRewriteGlobalFilter(
            ModifyResponseBodyGatewayFilterFactory modifyResponseBodyFactory,
            OpenApiServerPrefixResolver prefixResolver,
            ObjectMapper objectMapper) {

        RewriteFunction<String, String> rewriteFunction = (exchange, body) -> {
            if (body == null || body.isBlank()) {
                return Mono.justOrEmpty(body);
            }
            String path = exchange.getRequest().getURI().getPath();
            return prefixResolver.resolve(path)
                    .map(prefix -> rewriteBody(exchange, body, prefix, objectMapper))
                    .orElseGet(() -> Mono.just(body));
        };

        ModifyResponseBodyGatewayFilterFactory.Config config = new ModifyResponseBodyGatewayFilterFactory.Config();
        config.setInClass(String.class);
        config.setOutClass(String.class);
        config.setRewriteFunction(rewriteFunction);
        GatewayFilter modifyResponseBodyFilter = modifyResponseBodyFactory.apply(config);

        return new OrderedGlobalFilter((exchange, chain) -> {
            String path = exchange.getRequest().getURI().getPath();
            if (!prefixResolver.isOpenApiSpecPath(path) || prefixResolver.resolve(path).isEmpty()) {
                return chain.filter(exchange);
            }
            return modifyResponseBodyFilter.filter(exchange, chain);
        }, NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1);
    }

    private static Mono<String> rewriteBody(
            ServerWebExchange exchange,
            String body,
            String prefix,
            ObjectMapper objectMapper) {
        try {
            HttpHeaders headers = exchange.getResponse().getHeaders();
            byte[] rewritten = OpenApiServerRewriteService.rewrite(
                    body.getBytes(StandardCharsets.UTF_8), prefix, objectMapper, headers);
            log.debug("OpenAPI servers rewritten: {} -> {}", exchange.getRequest().getURI().getPath(), prefix);
            return Mono.just(new String(rewritten, StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.warn("OpenAPI rewrite failed for {}: {}", exchange.getRequest().getURI().getPath(), e.getMessage());
            return Mono.just(body);
        }
    }

    private record OrderedGlobalFilter(GatewayFilter delegate, int order) implements GlobalFilter, Ordered {

        @Override
        public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
            return delegate.filter(exchange, chain);
        }

        @Override
        public int getOrder() {
            return order;
        }
    }
}
