/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import ru.beeline.fdmgateway.service.AuthorizeService;
import ru.beeline.fdmgateway.utils.eauth.EAuthHelper;
import ru.beeline.fdmgateway.utils.eauth.EAuthKey;

@RestController
public class ApplicationController {

    @Autowired
    AuthorizeService authorizeService;

    @Value("${app.version}")
    private String appVersion;

    @Value("${app.name}")
    private String appName;

    @GetMapping("/")
    public Mono<String> getData() {
        return Mono.just("Welcome " + appName + " " + appVersion);
    }

    @GetMapping("/api/runtime/v1/eauthkey")
    public Mono<EAuthKey> getEAuthKey() {
        return Mono.fromCallable(EAuthHelper::getEAuthKey)
                .subscribeOn(Schedulers.boundedElastic());
    }

    @DeleteMapping("/cache")
    public Mono<ResponseEntity<Void>> clearCache() {
        return Mono.fromRunnable(() -> authorizeService.invalidateAll())
                .subscribeOn(Schedulers.boundedElastic())
                .then(Mono.just(ResponseEntity.ok().build()));
    }

    @DeleteMapping("/cache/{login}")
    public Mono<ResponseEntity<Void>> removeFromCacheByLogin(@PathVariable String login) {
        return Mono.fromRunnable(() -> authorizeService.invalidateUser(login))
                .subscribeOn(Schedulers.boundedElastic())
                .then(Mono.just(ResponseEntity.ok().build()));
    }
}
