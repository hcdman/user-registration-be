package com.exercise.user_registration_be.controller;

import com.exercise.user_registration_be.dto.LoginRequest;
import com.exercise.user_registration_be.model.User;
import com.exercise.user_registration_be.response.ApiResponse;
import com.exercise.user_registration_be.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    @PostMapping("/register")
    public ResponseEntity<ApiResponse> register(@RequestBody User user) {
        try {
            if(userService.checkExistedEmail(user.getEmail()))
            {
                ApiResponse apiResponse = ApiResponse.builder().success(false).message("Email already exist!").data(null).build();
                return new ResponseEntity<>(apiResponse,HttpStatus.BAD_REQUEST);
            }
            if(userService.checkExistedUserName(user.getUsername()))
            {
                ApiResponse apiResponse = ApiResponse.builder().success(false).message("User name already exist!").data(null).build();
                return new ResponseEntity<>(apiResponse,HttpStatus.BAD_REQUEST);
            }
            User registeredUser = userService.registerUser(user);
            ApiResponse apiResponse = ApiResponse.builder().success(true).message("User registered successfully!").data(registeredUser).build();
            return new ResponseEntity<>(apiResponse,HttpStatus.CREATED);
        } catch (Exception e) {
            ApiResponse response = new ApiResponse(false, "Register failed", null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse> loginUser(@RequestBody LoginRequest loginRequest) {
        try {
            boolean isAuthenticated = userService.authenticate(loginRequest.getUserName(), loginRequest.getPassword());
            if (isAuthenticated) {
                Optional<User> user = userService.getUserByUserName(loginRequest.getUserName());
                String token = userService.generateToken(loginRequest.getUserName(),loginRequest.getPassword());
                ApiResponse response = new ApiResponse(true, token, user.get());
                return new ResponseEntity<>(response, HttpStatus.OK);
            } else {
                ApiResponse response = new ApiResponse(false, "Invalid password", loginRequest.getUserName());
                return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
            }
        } catch (UsernameNotFoundException e) {
            ApiResponse response = new ApiResponse(false, "User not found", null);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            ApiResponse response = new ApiResponse(false, e.getMessage(), null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    @GetMapping("/profile")
    public ResponseEntity<ApiResponse> getProfile(@RequestHeader("Authorization") String authorizationHeader) {
        try {
            String extractedToken = authorizationHeader.substring(7);
            User user = userService.getUserDetailFromToken(extractedToken);
            ApiResponse response = new ApiResponse(true, "Get profile successfully!", user);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            ApiResponse response = new ApiResponse(false, "Get data profile failed", null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
