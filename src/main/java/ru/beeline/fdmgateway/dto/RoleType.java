package ru.beeline.fdmgateway.dto;

import lombok.Getter;

@Getter
public enum RoleType {
    DEFAULT("Сотрудник"),
    ADMINISTRATOR("Администратор");

    private final String roleName;

    private static final RoleType[] values = RoleType.values();

    RoleType(String roleName) {
        this.roleName = roleName;
    }

    public static String getNameById(int id) {
        return values[id].getRoleName();
    }
}