package com.exercise.user_registration_be.controller;

import com.exercise.user_registration_be.dto.LoginRequest;
import com.exercise.user_registration_be.model.User;
import com.exercise.user_registration_be.response.ApiResponse;
import com.exercise.user_registration_be.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
            if(userService.checkExistedUserName(user.getUserName()))
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

                ApiResponse response = new ApiResponse(true, "Login successfully!", loginRequest.getUserName());
                return new ResponseEntity<>(response, HttpStatus.OK);
            } else {
                ApiResponse response = new ApiResponse(false, "Invalid password", loginRequest.getUserName());
                return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
            }
        } catch (UsernameNotFoundException e) {
            ApiResponse response = new ApiResponse(false, "User not found", null);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            ApiResponse response = new ApiResponse(false, "Login failed", null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
