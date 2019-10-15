package cn.com.cloud.account.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author twg
 * @since 2019/7/2
 */
@Controller
public class HomeController {

    @RequestMapping("/home")
    public String home(){
        return "home";
    }
}
