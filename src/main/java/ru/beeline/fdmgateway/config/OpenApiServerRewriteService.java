/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.HttpHeaders;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

final class OpenApiServerRewriteService {

    private OpenApiServerRewriteService() {
    }

    static byte[] rewrite(byte[] content, String prefix, ObjectMapper objectMapper, HttpHeaders headers)
            throws IOException {
        byte[] jsonBytes = maybeDecompress(content, headers);
        JsonNode root = objectMapper.readTree(jsonBytes);
        if (!root.isObject()) {
            return content;
        }
        ObjectNode objectNode = (ObjectNode) root;
        if (objectNode.has("openapi")) {
            rewriteOpenApi3(objectNode, prefix, objectMapper);
        } else if (objectNode.has("swagger")) {
            rewriteSwagger2(objectNode, prefix, objectMapper);
        } else {
            return content;
        }
        headers.remove(HttpHeaders.CONTENT_ENCODING);
        return objectMapper.writeValueAsBytes(objectNode);
    }

    private static byte[] maybeDecompress(byte[] content, HttpHeaders headers) throws IOException {
        boolean gzipHeader = headers.getFirst(HttpHeaders.CONTENT_ENCODING) != null
                && headers.getFirst(HttpHeaders.CONTENT_ENCODING).toLowerCase().contains("gzip");
        boolean gzipMagic = content.length >= 2 && content[0] == (byte) 0x1f && content[1] == (byte) 0x8b;
        if (!gzipHeader && !gzipMagic) {
            return content;
        }
        try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(content));
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            gzip.transferTo(out);
            return out.toByteArray();
        }
    }

    private static final String BEARER_SCHEME = "bearerAuth";
    private static final String BEARER_DESCRIPTION = "JWT токен (без префикса Bearer)";

    private static void rewriteOpenApi3(ObjectNode root, String prefix, ObjectMapper objectMapper) {
        ArrayNode servers = objectMapper.createArrayNode();
        ObjectNode server = objectMapper.createObjectNode();
        server.put("url", prefix);
        server.put("description", "via Gateway");
        servers.add(server);
        root.set("servers", servers);
        ensureBearerSecurity(root, objectMapper);
    }

    private static void ensureBearerSecurity(ObjectNode root, ObjectMapper objectMapper) {
        ObjectNode components = root.has("components") && root.get("components").isObject()
                ? (ObjectNode) root.get("components")
                : objectMapper.createObjectNode();
        ObjectNode securitySchemes = components.has("securitySchemes") && components.get("securitySchemes").isObject()
                ? (ObjectNode) components.get("securitySchemes")
                : objectMapper.createObjectNode();

        String existingBearerSchemeName = null;
        var fieldNames = securitySchemes.fieldNames();
        while (fieldNames.hasNext()) {
            String name = fieldNames.next();
            JsonNode schemeNode = securitySchemes.get(name);
            if (schemeNode.isObject() && isBearerLikeScheme((ObjectNode) schemeNode)) {
                ((ObjectNode) schemeNode).put("description", BEARER_DESCRIPTION);
                existingBearerSchemeName = name;
            }
        }

        String schemeForSecurity = existingBearerSchemeName;
        if (existingBearerSchemeName == null) {
            securitySchemes.set(BEARER_SCHEME, createBearerScheme(objectMapper));
            schemeForSecurity = BEARER_SCHEME;
        }

        components.set("securitySchemes", securitySchemes);
        root.set("components", components);

        if (!root.has("security") || root.get("security").isEmpty()) {
            ArrayNode security = objectMapper.createArrayNode();
            ObjectNode requirement = objectMapper.createObjectNode();
            requirement.set(schemeForSecurity, objectMapper.createArrayNode());
            security.add(requirement);
            root.set("security", security);
        }
    }

    private static ObjectNode createBearerScheme(ObjectMapper objectMapper) {
        ObjectNode bearer = objectMapper.createObjectNode();
        bearer.put("type", "http");
        bearer.put("scheme", "bearer");
        bearer.put("bearerFormat", "JWT");
        bearer.put("description", BEARER_DESCRIPTION);
        return bearer;
    }

    private static boolean isBearerLikeScheme(ObjectNode scheme) {
        if (!scheme.has("type")) {
            return false;
        }
        return switch (scheme.get("type").asText()) {
            case "http" -> "bearer".equalsIgnoreCase(scheme.path("scheme").asText());
            case "apiKey" -> "header".equalsIgnoreCase(scheme.path("in").asText())
                    && "Authorization".equalsIgnoreCase(scheme.path("name").asText());
            default -> false;
        };
    }

    private static void rewriteSwagger2(ObjectNode root, String prefix, ObjectMapper objectMapper) {
        root.remove("host");
        root.put("basePath", prefix);
        if (!root.has("schemes")) {
            ArrayNode schemes = objectMapper.createArrayNode();
            schemes.add("https");
            schemes.add("http");
            root.set("schemes", schemes);
        }
        ObjectNode securityDefinitions = objectMapper.createObjectNode();
        ObjectNode bearer = objectMapper.createObjectNode();
        bearer.put("type", "apiKey");
        bearer.put("name", "Authorization");
        bearer.put("in", "header");
        bearer.put("description", BEARER_DESCRIPTION);
        securityDefinitions.set(BEARER_SCHEME, bearer);
        root.set("securityDefinitions", securityDefinitions);
        ArrayNode security = objectMapper.createArrayNode();
        ObjectNode requirement = objectMapper.createObjectNode();
        requirement.set(BEARER_SCHEME, objectMapper.createArrayNode());
        security.add(requirement);
        root.set("security", security);
    }
}
