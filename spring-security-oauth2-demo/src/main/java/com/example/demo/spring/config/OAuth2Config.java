package com.example.demo.spring.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * @author twg
 * @since 2019/7/4
 */
@Configuration
public class OAuth2Config {

    @Bean
    public PasswordEncoder passwordEncoder() {
        DelegatingPasswordEncoder passwordEncoder = (DelegatingPasswordEncoder) PasswordEncoderFactories.createDelegatingPasswordEncoder();
        passwordEncoder.setDefaultPasswordEncoderForMatches(NoOpPasswordEncoder.getInstance());
        return passwordEncoder;
    }

    @Bean
    public TokenStore tokenStore() {
        return new InMemoryTokenStore();
    }

    @Configuration
    @EnableAuthorizationServer
    public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

        @Autowired
        private ClientDetailsService clientDetailsService;

        @Autowired(required = false)
        private AuthenticationManager authenticationManager;

        @Autowired(required = false)
        private AccessTokenConverter accessTokenConverter;

        /**
         * token 持久化接口默认InMemoryTokenStore
         */
        @Autowired(required = false)
        private TokenStore tokenStore;

        /**
         * token 生成器，默认CompositeTokenGranter,通过client_id 验证grant_type后再通过tokenService#createAccessToken 生成token
         */
        @Autowired(required = false)
        private TokenGranter tokenGranter;

        @Autowired(required = false)
        private WebResponseExceptionTranslator<OAuth2Exception> exceptionTranslator;

        @Autowired
        private AccessDeniedHandler accessDeniedHandler;

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//            if (Objects.isNull(clientDetailsService)) {
            clients.inMemory().withClient("oauth")
                    .resourceIds("oauth")
                    .authorizedGrantTypes("authorization_code", "implicit", "client_credentials")
                    .authorities("ROLE_CLIENT")
                    .scopes("read", "write")
                    .secret("secret")
                    .redirectUris("http://localhost:8080/tonr2/sparklr/photos");

            // @formatter:on
//            } else {
//                clients.withClientDetails(clientDetailsService);
//            }
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints
                    .accessTokenConverter(accessTokenConverter)
                    /**
                     * password 模式时需要
                     */
                    .authenticationManager(authenticationManager)
                    .tokenStore(tokenStore)
                    .tokenGranter(tokenGranter)
                    .tokenServices(tokenServices())
                    .exceptionTranslator(exceptionTranslator);
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
            security
                    .accessDeniedHandler(accessDeniedHandler)
                    .authenticationEntryPoint((request, response, authException) -> {
                        System.out.println("==========authException =====" + authException);
                        response.sendRedirect("/u/login?return_to=" + request.getServletPath());
                    })
                    .realm("oauth/demo")
                    .passwordEncoder(passwordEncoder())
                    .allowFormAuthenticationForClients();

        }

        @Bean
        public DefaultTokenServices tokenServices() {
            DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
            defaultTokenServices.setTokenStore(tokenStore);
            defaultTokenServices.setClientDetailsService(clientDetailsService);
            return defaultTokenServices;
        }
    }
}
