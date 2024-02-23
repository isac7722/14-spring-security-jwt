package org.example.jwttest.dto;

import lombok.Data;

@Data
public class MemberRequestDto {
    private String email;
    private String password;
}
