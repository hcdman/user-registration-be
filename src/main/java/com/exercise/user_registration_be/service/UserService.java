package com.exercise.user_registration_be.service;
import com.exercise.user_registration_be.model.User;
import com.exercise.user_registration_be.repositories.UserRepository;
import com.exercise.user_registration_be.utils.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;
    private final AuthenticationManager authenticationManager;
    public User registerUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setCreatedAt(ZonedDateTime.now(ZoneId.of("Asia/Ho_Chi_Minh")).toLocalDateTime());
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
    public User getUserDetailFromToken(String token) throws Exception {
        if(jwtTokenUtil.isTokenExpired(token))
        {
            throw new Exception("Token is expired");
        }
        String userName = jwtTokenUtil.extractUserName(token);
        Optional<User> user = userRepository.findByUserName(userName);
        if(user.isPresent())
        {
            return user.get();
        }
        else {
            throw new Exception("User not found");
        }
    }
    public String generateToken(String userName, String password) {
        Optional<User> user = userRepository.findByUserName(userName);
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userName,password);
        authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        return jwtTokenUtil.generateToken(user.get());
    }
}
