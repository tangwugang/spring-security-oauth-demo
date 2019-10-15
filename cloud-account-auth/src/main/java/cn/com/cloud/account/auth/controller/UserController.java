package cn.com.cloud.account.auth.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author twg
 * @since 2019/7/2
 */
@RestController
public class UserController {

    @PostMapping("/me")
    public String getCurrentUser(Principal principal){
        System.out.println("UserController.getCurrentUser == " + principal);
        return principal.getName();
    }
}
