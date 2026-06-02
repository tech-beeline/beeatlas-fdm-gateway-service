package ru.beeline.fdmgateway.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import ru.beeline.fdmgateway.utils.jwt.JwtUtils;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Map;

@Slf4j
@Service
public class AuthSSOClient {

    private final String serverUrl;
    private final RestTemplate restTemplate;

    private static String accessToken;
    private static ZonedDateTime expiresAt;

    public AuthSSOClient(@Value("${integration.authsso-server-url}") String serverUrl,
                         RestTemplate restTemplate) {
        this.serverUrl = serverUrl;
        this.restTemplate = restTemplate;
    }

    public String getToken() {
        if (accessToken == null || expiresAt == null || expiresAt.isBefore(ZonedDateTime.now(ZoneId.of("UTC")))) {
            accessToken = obtainAccessToken();

            Object expObj = JwtUtils.encodeJWT(accessToken).get("exp");
            long epochSeconds;

            if (expObj instanceof Number) {
                epochSeconds = ((Number) expObj).longValue();
            } else if (expObj instanceof String) {
                String s = (String) expObj;
                try {
                    epochSeconds = Long.parseLong(s);
                } catch (NumberFormatException e) {
                    epochSeconds = Instant.parse(s).getEpochSecond();
                }
            } else {
                throw new IllegalStateException(
                        "Unsupported type for JWT claim \"exp\": " +
                                (expObj == null ? "null" : expObj.getClass()));
            }

            expiresAt = Instant.ofEpochSecond(epochSeconds).atZone(ZoneId.of("UTC"));
        }
        return accessToken;
    }

    public String obtainAccessToken() {
        try {
            ResponseEntity<String> response = restTemplate.postForEntity(serverUrl, null, String.class);

            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> responseMap = objectMapper.readValue(response.getBody(), Map.class);
            Object token = responseMap.get("access_token");
            if (token == null) {
                throw new RuntimeException("Missing access_token in response");
            }
            return token.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error while obtaining token from ambassador", e);
        }
    }
}

