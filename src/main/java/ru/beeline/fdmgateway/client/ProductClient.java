/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import ru.beeline.fdmgateway.dto.ApiSecretDto;
import ru.beeline.fdmgateway.exception.ServerErrorException;
import ru.beeline.fdmgateway.exception.UnauthorizedException;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

@Slf4j
@Service
public class ProductClient {

    private final String productServerUrl;
    private final RestTemplate restTemplate;

    @Autowired
    public ProductClient(@Value("${integration.products-server-url}") String productServerUrl,
                         RestTemplate restTemplate) {
        this.productServerUrl = productServerUrl;
        this.restTemplate = restTemplate;
    }

    public ApiSecretDto getServiceKey(String apiKey) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.add("SOURCE", "Sparx");
            return restTemplate.exchange(productServerUrl + "/api/v1/service/api-secret/key/" + apiKey,
                    HttpMethod.GET, new HttpEntity(headers), ApiSecretDto.class).getBody();
        } catch (HttpClientErrorException.NotFound e) {
            log.error("API key not found: {}", e.getMessage());
            throw new UnauthorizedException(e.getMessage());
        } catch (HttpServerErrorException e) {
            log.error("Server error: {}", e.getMessage());
            throw new ServerErrorException(e.getMessage());
        }
    }

    public ApiSecretDto getProductKey(String apiKey) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.add("SOURCE", "Sparx");
            return restTemplate.exchange(productServerUrl + "/api/v1/product/api-secret/" + apiKey,
                    HttpMethod.GET, new HttpEntity(headers), ApiSecretDto.class).getBody();
        } catch (HttpClientErrorException.NotFound e) {
            log.error("API key not found: {}", e.getMessage());
            throw new UnauthorizedException(e.getMessage());
        } catch (HttpServerErrorException e) {
            log.error("Server error: {}", e.getMessage());
            throw new ServerErrorException(e.getMessage());
        }
    }
}