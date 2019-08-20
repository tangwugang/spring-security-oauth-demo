package com.example.demo.spring.controller;

import com.example.demo.spring.model.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author twg
 * @since 2019/7/2
 */
@RestController
public class UserController {

    @GetMapping("/me")
    public User getCurrentUser(Principal principal){
        return new User(principal.getName());
    }
}
