/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

@Component
public class OpenApiServerPrefixResolver {

    private final List<Mapping> mappings;

    public OpenApiServerPrefixResolver(
            @Value("${path.products}") String products,
            @Value("${path.product2}") String product2,
            @Value("${path.project}") String project,
            @Value("${path.capability}") String capability,
            @Value("${path.capability2}") String capability2,
            @Value("${path.auth}") String auth,
            @Value("${path.user2}") String user2,
            @Value("${path.techradar}") String techradar,
            @Value("${path.techradar2}") String techradar2,
            @Value("${path.notification}") String notification,
            @Value("${path.notification2}") String notification2,
            @Value("${path.bpm}") String bpm,
            @Value("${path.camunda2}") String camunda2,
            @Value("${path.document}") String document,
            @Value("${path.documentv2}") String documentv2,
            @Value("${path.doc2}") String doc2,
            @Value("${path.graph}") String graph,
            @Value("${path.archgraph}") String archgraph,
            @Value("${path.structurizr}") String structurizr,
            @Value("${path.structurizr2}") String structurizr2,
            @Value("${path.dashboard}") String dashboard,
            @Value("${path.dashboard2}") String dashboard2,
            @Value("${path.pack-loader.all}") String packLoaderAll,
            @Value("${path.package2}") String package2,
            @Value("${path.cx.all}") String cxAll,
            @Value("${path.cx2}") String cx2,
            @Value("${path.chat}") String chat,
            @Value("${path.search}") String search,
            @Value("${path.ffmanager}") String ffManager
    ) {
        var list = new ArrayList<Mapping>();
        add(list, products, product2);
        add(list, product2, product2);
        add(list, project, project);
        add(list, capability, capability2);
        add(list, capability2, capability2);
        add(list, auth, user2);
        add(list, user2, user2);
        add(list, techradar, techradar2);
        add(list, techradar2, techradar2);
        add(list, notification, notification2);
        add(list, notification2, notification2);
        add(list, bpm, camunda2);
        add(list, camunda2, camunda2);
        add(list, document, doc2);
        add(list, documentv2, doc2);
        add(list, doc2, doc2);
        add(list, graph, archgraph);
        add(list, archgraph, archgraph);
        add(list, structurizr, structurizr2);
        add(list, structurizr2, structurizr2);
        add(list, dashboard, dashboard2);
        add(list, dashboard2, dashboard2);
        add(list, packLoaderAll, package2);
        add(list, package2, package2);
        add(list, cxAll, cx2);
        add(list, cx2, cx2);
        add(list, chat, chat);
        add(list, search, search);
        add(list, ffManager, ffManager);
        list.sort(Comparator.comparingInt((Mapping m) -> m.source.length()).reversed());
        this.mappings = List.copyOf(list);
    }

    private static void add(List<Mapping> list, String source, String prefix) {
        if (source != null && !source.isBlank() && prefix != null && !prefix.isBlank()) {
            list.add(new Mapping(source, prefix));
        }
    }

    public boolean isOpenApiSpecPath(String requestPath) {
        return requestPath.endsWith("/v3/api-docs")
                || requestPath.endsWith("/api-docs")
                || requestPath.endsWith("/openapi.json")
                || requestPath.contains("/swagger.json");
    }

    public Optional<String> resolve(String requestPath) {
        if ("/v3/api-docs".equals(requestPath)) {
            return Optional.of("/");
        }
        return mappings.stream()
                .filter(m -> requestPath.startsWith(m.source))
                .findFirst()
                .map(m -> m.prefix);
    }

    private record Mapping(String source, String prefix) {
    }
}
