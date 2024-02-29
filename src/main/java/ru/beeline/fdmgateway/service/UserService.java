package ru.beeline.fdmgateway.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import ru.beeline.fdmgateway.dto.UserInfoDTO;

import static ru.beeline.fdmgateway.utils.RestHelper.getRestTemplate;

@Slf4j
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

}
