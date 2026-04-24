package ru.beeline.fdmgateway.dto;

import lombok.Data;

import java.io.Serializable;

@Data
public class UserDropCacheMessage  implements Serializable {
    private String userLogin;
}

