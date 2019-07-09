package com.example.demo.spring.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author twg
 * @since 2019/7/8
 */
@RestController
public class TokenEndpointController {

    @GetMapping("/access_token")
    public String accessToken(){
        return "this is accessToken";
    }
}
