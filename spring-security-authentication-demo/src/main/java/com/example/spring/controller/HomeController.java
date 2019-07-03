package com.example.spring.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @author twg
 * @since 2019/7/2
 */
@Controller
public class HomeController {

    @GetMapping("/home")
    public String home(){
        return "home";
    }
}
