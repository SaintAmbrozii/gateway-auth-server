package com.example.authserver.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.CONTINUE)
public class UserIsExist extends RuntimeException{
    public UserIsExist(String message) {
        super(message);
    }
}
