package ru.beeline.fdmgateway.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.beeline.fdmgateway.utils.eauth.EAuthHelper;
import ru.beeline.fdmgateway.utils.eauth.EAuthKey;

@RestController
public class ApplicationController {

    @Value("${app.version}")
    private String appVersion;

    @Value("${app.name}")
    private String appName;


    @GetMapping("/")
    public String getData() {
        return "Welcome " + appName + " " + appVersion;
    }

    @GetMapping("/api/runtime/v1/eauthkey")
    public EAuthKey getEAuthKey() {
        return EAuthHelper.getEAuthKey();
    }
}
