package ru.beeline.fdmgateway.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import ru.beeline.fdmgateway.dto.UserInfo;

@Service
public class UserService {

    private final WebClient webClient;
    private final String userServerUrl;

    public UserService(@Value("${integration.user-server-url}") String userServerUrl) {
        this.webClient = WebClient.create();
        this.userServerUrl = userServerUrl;
    }

    public UserInfo getUserInfo(String login) {
        return webClient.get()
                .uri(userServerUrl + "/api/admin/v1/user/find?text=1&filter=1")
                .retrieve()
                .bodyToMono(UserInfo.class)
                .block();
    }
}