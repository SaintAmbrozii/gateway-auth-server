package com.example.authserver.controller;


import com.example.authserver.domain.User;
import com.example.authserver.dto.UserRegistrationDto;
import com.example.authserver.service.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("register")
    public User createUser(@RequestBody UserRegistrationDto userdto) {
        return userService.createUser(userdto);
    }

}
