package ru.beeline.fdmgateway.utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import ru.beeline.fdmgateway.utils.eauth.EAuthHelper;


@Component
public class PKBeanImpl {
    @Autowired
    EAuthHelper eAuthHelper;

    @Value("${jwks}")
    private String jwksUrl;

    public void runAfterObjectCreated() {
        eAuthHelper.getAndSavePublicKey(jwksUrl);
    }
}