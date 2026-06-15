/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.config;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestTemplateConfig {

    @Bean
    public RestTemplate restTemplate(
            @Value("${http-client.connect-timeout-ms:2000}") int connectTimeoutMs,
            @Value("${http-client.read-timeout-ms:8000}") int readTimeoutMs,
            @Value("${http-client.max-connections:200}") int maxConnections) {
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(connectTimeoutMs)
                .setSocketTimeout(readTimeoutMs)
                .setConnectionRequestTimeout(connectTimeoutMs)
                .build();
        CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setDefaultRequestConfig(requestConfig)
                .setMaxConnTotal(maxConnections)
                .setMaxConnPerRoute(maxConnections)
                .build();
        return new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient));
    }
}
