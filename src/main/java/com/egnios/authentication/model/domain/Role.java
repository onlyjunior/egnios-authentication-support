package com.egnios.authentication.model.domain;

import java.util.Arrays;
import java.util.Optional;

public enum Role {

    ANONYMOUS (0),
    ADMIN (1),
    CLIENT (2);

    private int code;

    Role(int code) {
        this.code = code;
    }

    public int code() {
        return this.code;
    }

    public static Optional<Role> valueOf(int code) {
        return Arrays.stream(Role.values())
            .filter(r -> r.code() == code)
            .findFirst();
    }
}
