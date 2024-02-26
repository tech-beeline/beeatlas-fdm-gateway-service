package ru.beeline.fdmgateway.dto;

import lombok.*;

import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class UserInfoDTO {

    private Long id;
    private List<Long> productsIds;

    private List<RoleType> roles;

    private List<PermissionType> permissions;

}
