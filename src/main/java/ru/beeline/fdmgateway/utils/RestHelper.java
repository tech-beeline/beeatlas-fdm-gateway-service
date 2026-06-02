/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.utils;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

public class RestHelper {

    private static final RestTemplate INSTANCE;

    static {
        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(5000)
                .setSocketTimeout(10000)
                .build();
        CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setDefaultRequestConfig(config)
                .setMaxConnTotal(20)
                .setMaxConnPerRoute(10)
                .build();
        INSTANCE = new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient));
    }

    public static RestTemplate getRestTemplate() {
        return INSTANCE;
    }
}
