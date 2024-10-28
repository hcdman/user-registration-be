package com.exercise.user_registration_be.service;

import com.exercise.user_registration_be.model.User;
import com.exercise.user_registration_be.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    public User registerUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setCreatedAt(LocalDateTime.now());
        return userRepository.save(user);
    }
    public boolean checkExistedEmail(String email)
    {
        Optional<User> user = userRepository.findByEmail(email);
        if(user.isPresent())
            return true;
        return false;
    }
    public boolean checkExistedUserName(String userName)
    {
        Optional<User> user = userRepository.findByUserName(userName);
        if(user.isPresent())
            return true;
        return false;
    }
    public Optional<User> getUserByUserName(String userName)
    {
        return userRepository.findByUserName(userName);
    }
    public boolean authenticate(String username, String password) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return passwordEncoder.matches(password, user.getPassword());
    }
}
