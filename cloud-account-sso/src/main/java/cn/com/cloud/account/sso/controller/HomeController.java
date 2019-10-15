package cn.com.cloud.account.sso.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author twg
 * @since 2019/10/14
 */
@Controller
public class HomeController {

    @RequestMapping("/u/home")
    public String home(){
        return "home";
    }
}
