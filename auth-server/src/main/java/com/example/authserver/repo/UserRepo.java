package com.example.authserver.repo;


import com.example.authserver.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepo extends JpaRepository<User,Long> {

    Optional<User> findByEmail(String email);
}
