/*
 * Copyright (c) 2024 PJSC VimpelCom
 */

package ru.beeline.fdmgateway.dto;

import lombok.*;

import java.util.Map;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class AuthorizeRequestDTO {

    private String email;
    private String fullName;
    private String idExt;
    private String path;
    private String method;
    private Map<String, String> queryParams;
}
