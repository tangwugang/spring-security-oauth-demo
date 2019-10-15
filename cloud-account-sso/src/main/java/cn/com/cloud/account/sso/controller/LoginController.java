package cn.com.cloud.account.sso.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;

/**
 * @author twg
 * @since 2019/7/2
 */
@Controller
public class LoginController {

    @GetMapping("/u/login")
    public String login(HttpServletRequest request) {
        String authentication_error = request.getParameter("authentication_error");
        System.out.println("========LoginController.login ==== " + authentication_error);
        return "login";
    }
}
