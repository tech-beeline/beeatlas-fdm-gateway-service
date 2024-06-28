package ru.beeline.fdmgateway.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ru.beeline.fdmgateway.client.UserClient;
import ru.beeline.fdmlib.dto.auth.UserInfoDTO;

import java.util.Date;
import java.util.HashMap;

@Slf4j
@Service
public class UserService {
    private final static HashMap<String, UserInfoDTO> userInfoCache = new HashMap<>();
    private final UserClient userClient;
    private final Long cacheExpiration;
    private Date lastInvalidate = new Date();

    public UserService(UserClient userClient,
                       @Value("${spring.cache.expiration}") Long cacheExpiration) {
        this.userClient = userClient;
        this.cacheExpiration = cacheExpiration;
    }

    public UserInfoDTO getUserInfo(String email, String fullName, String idExt) {
        if (isExpired()) {
            userInfoCache.clear();
            lastInvalidate = new Date();
        }

        if (!userInfoCache.containsKey(email)) {
            userInfoCache.put(email, userClient.getUserInfo(email, fullName, idExt));
        }
        return userInfoCache.get(email);
    }

    private boolean isExpired() {
        return new Date().getTime() > lastInvalidate.getTime() + cacheExpiration;
    }
}
