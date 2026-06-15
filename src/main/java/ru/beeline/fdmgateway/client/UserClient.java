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


@Slf4j
@Service
public class UserClient {
    private final String userServerUrl;
    private final RestTemplate restTemplate;

    public UserClient(@Value("${integration.auth-server-url}") String userServerUrl,
                      RestTemplate restTemplate) {
        this.userServerUrl = userServerUrl;
        this.restTemplate = restTemplate;
    }

    public AuthorizeResponseDTO authorize(AuthorizeRequestDTO request) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<AuthorizeRequestDTO> entity = new HttpEntity<>(request, headers);
            return restTemplate
                    .exchange(userServerUrl + "/api/v1/authorize",
                            HttpMethod.POST, entity, AuthorizeResponseDTO.class)
                    .getBody();
        } catch (Exception e) {
            log.error("authorize call failed: " + e.getMessage());
            return null;
        }
    }
}
