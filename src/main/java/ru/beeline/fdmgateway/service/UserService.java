package ru.beeline.fdmgateway.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import ru.beeline.fdmgateway.dto.UserInfoDTO;

@Service
public class UserService {

    private final WebClient webClient;
    private final String userServerUrl;

    public UserService(@Value("${integration.user-server-url}") String userServerUrl) {
        this.webClient = WebClient.create();
        this.userServerUrl = userServerUrl;
    }

    public UserInfoDTO getUserInfo(String email, String fullName, String idExt) {
        String login = email.substring(0, email.indexOf("@"));
        return webClient.get()
                .uri(userServerUrl + "/api/admin/v1/user/" + login + "/info?&email=" + email + "&fullName=" + fullName + "&idExt=" + idExt)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .bodyToMono(UserInfoDTO.class)
                .block();
    }
}