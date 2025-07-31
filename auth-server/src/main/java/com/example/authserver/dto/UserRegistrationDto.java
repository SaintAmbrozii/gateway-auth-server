package com.example.authserver.dto;

import lombok.Data;

@Data
public class UserRegistrationDto {

    private String name;
    private String lastname;
    private String surname;
    private String address;
    private String email;
    private String password;

}
