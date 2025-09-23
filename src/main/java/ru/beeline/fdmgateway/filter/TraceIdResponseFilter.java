package ru.beeline.fdmgateway.filter;


import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.stereotype.Component;

import java.io.IOException;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.context.propagation.TextMapSetter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;

@Component
public class TraceIdResponseFilter implements GlobalFilter {

    private static final String TRACE_ID_HEADER = "traceparent";
    private final W3CTraceContextPropagator propagator = W3CTraceContextPropagator.getInstance();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return chain.filter(exchange)
                .then(Mono.fromRunnable(() -> {
                    String traceId = Span.current().getSpanContext().getTraceId();
                    if (traceId != null && !traceId.isEmpty()) {
                        exchange.getResponse().getHeaders().add(TRACE_ID_HEADER, generateTraceParentHeader());
                    }
                }));
    }

    private String generateTraceParentHeader() {
        return Span.current().getSpanContext().getTraceState().toString();
    }
}