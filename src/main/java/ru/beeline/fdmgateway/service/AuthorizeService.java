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
    private final UserService userService;

    private final ConcurrentHashMap<String, AuthorizeResponseDTO> cache = new ConcurrentHashMap<>();
    private volatile Date lastInvalidate = new Date();

    public AuthorizeService(UserClient userClient, UserService userService) {
        this.userClient = userClient;
        this.userService = userService;
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
                                          Map<String, String> queryParams) {
        if (isCacheExpired()) {
            cache.clear();
            lastInvalidate = new Date();
        }

        String login = tokenData.getEmail().substring(0, tokenData.getEmail().indexOf("@")).toLowerCase();
        String cacheKey = login + "|" + method + "|" + path;

        AuthorizeResponseDTO cached = cache.get(cacheKey);
        if (cached != null) {
            return cached;
        }

        AuthorizeRequestDTO request = buildRequest(tokenData, method, path, queryParams, login);
        AuthorizeResponseDTO response = userClient.authorize(request);

        if (response != null) {
            cache.put(cacheKey, response);
            syncToUserCache(login, response);
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

    private AuthorizeRequestDTO buildRequest(JwtUserData tokenData, String method, String path,
                                              Map<String, String> queryParams, String login) {
        UserInfoDTO cached = userService.getCachedUser(login);
        AuthorizeRequestDTO.AuthorizeRequestDTOBuilder builder = AuthorizeRequestDTO.builder()
                .email(tokenData.getEmail())
                .fullName(tokenData.getFullName())
                .idExt(tokenData.getEmployeeNumber())
                .path(path)
                .method(method)
                .queryParams(queryParams);

        if (cached != null && cached.getId() != null) {
            builder.userId(cached.getId())
                    .roles(cached.getRoles())
                    .productIds(cached.getProductsIds())
                    .permissions(cached.getPermissions() != null
                            ? cached.getPermissions().stream().map(Enum::name).collect(Collectors.toList())
                            : null);
        }
        return builder.build();
    }

    private void syncToUserCache(String login, AuthorizeResponseDTO response) {
        if (response.getUserId() != null) {
            UserInfoDTO existing = userService.getCachedUser(login);
            if (existing == null) {
                userService.putToCache(login, toUserInfo(response));
            }
        }
    }

    private boolean isCacheExpired() {
        return new Date().getTime() > lastInvalidate.getTime() + AUTHORIZE_CACHE_TTL_MS;
    }
}
