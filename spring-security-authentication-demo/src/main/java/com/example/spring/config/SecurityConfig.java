package com.example.spring.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * @author twg
 * @since 2019/7/2
 * 身份认证服务
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/u/login").permitAll()
                .anyRequest().hasRole("USER") //url 访问是否拥有user角色
                .anyRequest().authenticated()
                .and()
                .exceptionHandling()
                .accessDeniedPage("/u/login?authorization_error=true")
                .and()
                .sessionManagement()
                .invalidSessionUrl("/u/login?error=invalid_session")
                /**
                 * 控制客户端数量
                 */
//                .maximumSessions(1)
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
//                .enableSessionUrlRewriting(true)
                .and()
                .csrf()
                .disable()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/u/login")
                .invalidateHttpSession(true)
                .and()
                .formLogin()
                .loginProcessingUrl("/login")
                .failureUrl("/u/login?authentication_error=true")
                .loginPage("/u/login");
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.debug(true).ignoring().antMatchers("/webjars/**", "/images/**", "/oauth/uncache_approvals", "/oauth/cache_approvals");
    }

    @Override
    public UserDetailsService userDetailsService() {
        // ensure the passwords are encoded properly
        User.UserBuilder users = User.withDefaultPasswordEncoder();
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(users.username("security").password("security").roles("USER").build());
        manager.createUser(users.username("admin").password("admin").roles("USER", "ADMIN").build());
        return manager;
    }
}
