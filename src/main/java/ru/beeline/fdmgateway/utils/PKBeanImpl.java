package ru.beeline.fdmgateway.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import static ru.beeline.fdmgateway.utils.eauth.EAuthHelper.getAndSavePublicKey;


@Component
public class PKBeanImpl {

    @Value("${jwks}")
    private String jwksUrl;

    public void runAfterObjectCreated() {
        getAndSavePublicKey(jwksUrl);
    }
}