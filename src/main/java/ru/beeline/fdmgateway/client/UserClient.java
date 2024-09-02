package ru.beeline.fdmgateway.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import ru.beeline.fdmlib.dto.auth.UserInfoDTO;


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

    public UserInfoDTO getUserInfo(String email, String fullName, String idExt) {
        String login = email.substring(0, email.indexOf("@"));
        UserInfoDTO userInfoDto = null;
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> entity = new HttpEntity<>(headers);

            userInfoDto = restTemplate.exchange(userServerUrl + "/api/admin/v1/user/" + login + "/info?&email=" + email + "&fullName=" + fullName + "&idExt=" + idExt,
                    HttpMethod.GET, entity, UserInfoDTO.class).getBody();
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return userInfoDto;
    }

}
