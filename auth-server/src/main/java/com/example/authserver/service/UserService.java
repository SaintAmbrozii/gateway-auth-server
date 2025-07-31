package com.example.authserver.service;



import com.example.authserver.domain.Roles;
import com.example.authserver.domain.User;
import com.example.authserver.dto.UserRegistrationDto;
import com.example.authserver.repo.UserRepo;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
public class UserService {

    private final UserRepo userRepo;

    private final PasswordEncoder encoder;



    public UserService(UserRepo userRepo, PasswordEncoder encoder) {
        this.userRepo = userRepo;
        this.encoder = encoder;
    }

    public User createUser(UserRegistrationDto userdto) {
        User newUser = new User();
        newUser.setName(userdto.getName());
        newUser.setEmail(userdto.getEmail());
        newUser.setLastname(userdto.getLastname());
        newUser.setSurname(userdto.getSurname());
        newUser.setAddress(userdto.getAddress());
        newUser.setPassword(encoder.encode(userdto.getPassword()));
        newUser.setAuthority(Collections.singleton(Roles.ROLE_USER));
      return   userRepo.save(newUser);
    }

    public List<User> findAll() {
        return userRepo.findAll();
    }

}
