/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.utils;

import java.util.Set;

public class Constants {
    public static final String USER_ID_HEADER = "user-id";
    public static final String USER_PERMISSION_HEADER = "user-permission";
    public static final String USER_PRODUCTS_IDS_HEADER = "user-products-ids";
    public static final String USER_ROLES_HEADER = "user-roles";

    /**
     * Пути собственной статики/служебных ручек гейтвея (swagger-ui, actuator и т.п.),
     * которые не проксируются на бэкенды и не требуют авторизации.
     */
    public static final Set<String> GATEWAY_INTERNAL_PATHS = Set.of(
            "/api-docs",
            "/favicon.ico",
            "/swagger",
            "/openapi.json",
            "/.well-known",
            "/actuator/prometheus",
            "/actuator/health",
            "/cache",
            "/api-gateway/capability/v2/tech/",
            "/eauthkey"
    );
}