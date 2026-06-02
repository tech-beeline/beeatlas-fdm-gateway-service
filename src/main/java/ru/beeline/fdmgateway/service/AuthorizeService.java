/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import ru.beeline.fdmgateway.client.UserClient;
import ru.beeline.fdmgateway.dto.AuthorizeRequestDTO;
import ru.beeline.fdmgateway.dto.AuthorizeResponseDTO;
import ru.beeline.fdmgateway.dto.PermissionTypeDTO;
import ru.beeline.fdmgateway.dto.UserInfoDTO;
import ru.beeline.fdmgateway.utils.jwt.JwtUserData;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@Service
public class AuthorizeService {

    private static final long AUTHORIZE_CACHE_TTL_MS = 60_000L;

    private final UserClient userClient;

    private final ConcurrentHashMap<String, AuthorizeResponseDTO> cache = new ConcurrentHashMap<>();
    private volatile Date lastInvalidate = new Date();

    public AuthorizeService(UserClient userClient) {
        this.userClient = userClient;
    }

    public void invalidateAll() {
        cache.clear();
        lastInvalidate = new Date();
    }

    public void invalidateUser(String login) {
        String prefix = login.toLowerCase() + "|";
        cache.keySet().removeIf(k -> k.startsWith(prefix));
    }

    public AuthorizeResponseDTO authorize(JwtUserData tokenData, String method, String path,
                                          Map<String, String> queryParams, String bodyJson) {
        // requests with body content are not cached — body can differ across calls to the same path
        boolean cacheable = bodyJson == null;

        if (cacheable) {
            if (isCacheExpired()) {
                cache.clear();
                lastInvalidate = new Date();
                log.info("[PERF] authorize cache cleared (TTL expired)");
            }
            String login = tokenData.getEmail().substring(0, tokenData.getEmail().indexOf("@")).toLowerCase();
            String cacheKey = login + "|" + method + "|" + path;
            AuthorizeResponseDTO cached = cache.get(cacheKey);
            if (cached != null) {
                log.debug("[PERF] authorize cache HIT login={} {} {}", login, method, path);
                return cached;
            }

            log.info("[PERF] authorize cache MISS login={} {} {}", login, method, path);
            AuthorizeRequestDTO request = AuthorizeRequestDTO.builder()
                    .email(tokenData.getEmail())
                    .fullName(tokenData.getFullName())
                    .idExt(tokenData.getEmployeeNumber())
                    .path(path)
                    .method(method)
                    .queryParams(queryParams)
                    .build();

            long t0 = System.currentTimeMillis();
            AuthorizeResponseDTO response = userClient.authorize(request);
            log.info("[PERF] fdm-auth call login={} {} {} took {}ms -> {}",
                    login, method, path, System.currentTimeMillis() - t0,
                    response != null ? response.getDecision() : "null(timeout)");
            if (response != null) {
                if (response.getMessage() != null) {
                    log.warn("fdm-auth authorize: {}", response.getMessage());
                }
                cache.put(cacheKey, response);
            }
            return response;
        }

        String login = tokenData.getEmail().substring(0, tokenData.getEmail().indexOf("@")).toLowerCase();
        AuthorizeRequestDTO request = AuthorizeRequestDTO.builder()
                .email(tokenData.getEmail())
                .fullName(tokenData.getFullName())
                .idExt(tokenData.getEmployeeNumber())
                .path(path)
                .method(method)
                .queryParams(queryParams)
                .bodyJson(bodyJson)
                .build();

        long t0 = System.currentTimeMillis();
        AuthorizeResponseDTO response = userClient.authorize(request);
        log.info("[PERF] fdm-auth call (no-cache POST) login={} {} {} took {}ms -> {}",
                login, method, path, System.currentTimeMillis() - t0,
                response != null ? response.getDecision() : "null(timeout)");
        if (response != null && response.getMessage() != null) {
            log.warn("fdm-auth authorize: {}", response.getMessage());
        }
        return response;
    }

    public UserInfoDTO toUserInfo(AuthorizeResponseDTO response) {
        List<PermissionTypeDTO> perms = response.getPermissions() != null
                ? response.getPermissions().stream()
                        .map(p -> {
                            try { return PermissionTypeDTO.valueOf(p); } catch (Exception e) { return null; }
                        })
                        .filter(Objects::nonNull)
                        .collect(Collectors.toList())
                : List.of();
        return UserInfoDTO.builder()
                .id(response.getUserId())
                .productsIds(response.getProductIds())
                .roles(response.getRoles())
                .permissions(perms)
                .build();
    }

    private boolean isCacheExpired() {
        return new Date().getTime() > lastInvalidate.getTime() + AUTHORIZE_CACHE_TTL_MS;
    }
}
