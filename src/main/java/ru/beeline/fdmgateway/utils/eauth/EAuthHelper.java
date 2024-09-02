package ru.beeline.fdmgateway.utils.eauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;



@Slf4j
@Component
public class EAuthHelper {

    @Autowired
    RestTemplate restTemplate;
    private static String keyUrl = "";
    private static EAuthKey eAuthKey;

    public EAuthKey getAndSavePublicKey(String url) {
        keyUrl = url;
        try {
            final String key = restTemplate.getForObject(url, String.class);
            if (key != null) {
                ObjectMapper mapper = new ObjectMapper();

                EAuthKeys keys = mapper.readValue(key, EAuthKeys.class);
                if (!keys.getKeys().isEmpty()) {
                    eAuthKey = keys.getKeys().get(0);
                    log.info("EAuth key сохранен: " + eAuthKey);
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return eAuthKey;
    }

    public EAuthKey getEAuthKey() {
        if (!keyUrl.isEmpty() && eAuthKey == null) {
            eAuthKey = getAndSavePublicKey(keyUrl);
        }
        return eAuthKey;
    }
}
