/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import ru.beeline.fdmgateway.dto.AuthorizeRequestDTO;
import ru.beeline.fdmgateway.dto.AuthorizeResponseDTO;
import ru.beeline.fdmgateway.dto.UserInfoDTO;

import java.util.Map;

import static ru.beeline.fdmgateway.utils.RestHelper.getRestTemplate;

@Slf4j
@Service
public class UserClient {
    private final String userServerUrl;

    public UserClient(@Value("${integration.auth-server-url}") String userServerUrl) {
        this.userServerUrl = userServerUrl;
    }
    public UserInfoDTO getUserInfo(String email, String fullName, String idExt) {
        String login = email.substring(0, email.indexOf("@"));
        UserInfoDTO userInfoDto = null;
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> entity = new HttpEntity<>(headers);

            final RestTemplate restTemplate = getRestTemplate();
            userInfoDto = restTemplate.exchange(userServerUrl + "/api/admin/v1/user/" + login + "/info?&email=" + email + "&fullName=" + fullName + "&idExt=" + idExt,
                    HttpMethod.GET, entity, UserInfoDTO.class).getBody();
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return userInfoDto;
    }

    public AuthorizeResponseDTO authorize(String email, String fullName, String idExt,
                                          String path, String method, Map<String, String> queryParams) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            AuthorizeRequestDTO request = AuthorizeRequestDTO.builder()
                    .email(email)
                    .fullName(fullName)
                    .idExt(idExt)
                    .path(path)
                    .method(method)
                    .queryParams(queryParams)
                    .build();

            return getRestTemplate().exchange(
                    userServerUrl + "/api/v1/authorize",
                    HttpMethod.POST,
                    new HttpEntity<>(request, headers),
                    AuthorizeResponseDTO.class
            ).getBody();
        } catch (Exception e) {
            log.error(e.getMessage());
            return null;
        }
    }
}
