/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.utils;

import org.springframework.web.client.RestTemplate;

public class RestHelper {

    public static RestTemplate getRestTemplate() {
        return new RestTemplate();
    }
}
