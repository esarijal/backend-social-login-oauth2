package com.erm.sociallogin.demo.controller;

import com.erm.sociallogin.demo.exception.ResourceNotFoundException;
import com.erm.sociallogin.demo.model.User;
import com.erm.sociallogin.demo.repository.UserRepository;
import com.erm.sociallogin.demo.security.CurrentUser;
import com.erm.sociallogin.demo.security.UserPrincipal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("user")
public class UserController {
    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("me")
    @PreAuthorize("hasRole('USER')")
    public User getMe(@CurrentUser UserPrincipal userPrincipal){
        return userRepository.findById(userPrincipal.getId())
                .orElseThrow(
                        () -> new ResourceNotFoundException("User", "id", userPrincipal.getId()));
    }
}
