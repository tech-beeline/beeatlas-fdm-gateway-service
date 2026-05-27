/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ru.beeline.fdmgateway.client.UserClient;
import ru.beeline.fdmgateway.dto.UserInfoDTO;

import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
public class UserService {
    private final static ConcurrentHashMap<String, UserInfoDTO> userInfoCache = new ConcurrentHashMap<>();
    private final UserClient userClient;
    private final Long cacheExpiration;
    private volatile Date lastInvalidate = new Date();

    public UserService(UserClient userClient,
                       @Value("${spring.cache.expiration}") Long cacheExpiration) {
        this.userClient = userClient;
        this.cacheExpiration = cacheExpiration;
    }

    public void removeFromCache() {
        userInfoCache.clear();
        lastInvalidate = new Date();
    }

    public void removeFromCache(String login) {
        userInfoCache.remove(login.toLowerCase());
    }

    public UserInfoDTO getCachedUser(String login) {
        return userInfoCache.get(login.toLowerCase());
    }

    public void putToCache(String login, UserInfoDTO userInfo) {
        if (userInfo != null) {
            userInfoCache.put(login.toLowerCase(), userInfo);
        }
    }

    public UserInfoDTO getUserInfo(String email, String fullName, String idExt) {
        String login = email.substring(0, email.indexOf("@")).toLowerCase();

        if (isExpired()) {
            userInfoCache.clear();
            lastInvalidate = new Date();
        }

        UserInfoDTO cached = userInfoCache.get(login);
        if (cached != null && cached.getId() != null
                && cached.getPermissions() != null && !cached.getPermissions().isEmpty()) {
            return cached;
        }

        UserInfoDTO fresh = userClient.getUserInfo(email, fullName, idExt);
        if (fresh != null) {
            userInfoCache.put(login, fresh);
        }
        return fresh;
    }

    private boolean isExpired() {
        return new Date().getTime() > lastInvalidate.getTime() + cacheExpiration;
    }
}
