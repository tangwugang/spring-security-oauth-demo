package cn.com.cloud.account.sso.config;

import cn.com.cloud.account.sso.handler.CustomUserApprovalHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
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
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
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

        @Autowired
        private UserApprovalHandler userApprovalHandler;

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//            if (Objects.isNull(clientDetailsService)) {
            clients.inMemory().withClient("tonr-with-redirect")
//                    .resourceIds("oauth")
                    .authorizedGrantTypes("authorization_code", "implicit", "client_credentials")
                    .authorities("ROLE_CLIENT")
                    .scopes("read", "write")
                    .secret("secret")
                    .autoApprove(true)
                    .redirectUris("http://localhost:8082/login/demo");

            // @formatter:on
//            } else {
//                clients.withClientDetails(clientDetailsService);
//            }
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints
                    .pathMapping("/oauth/token", "/oauth/access_token")
                    .accessTokenConverter(accessTokenConverter)
                    .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST)
                    /**
                     * password 模式时需要
                     */
                    .authenticationManager(authenticationManager)
                    .userApprovalHandler(userApprovalHandler)
                    .tokenStore(tokenStore)
                    .tokenGranter(tokenGranter)
                    .tokenServices(tokenServices())
                    .exceptionTranslator(exceptionTranslator);
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
            security
                    .accessDeniedHandler(accessDeniedHandler)
//                    .authenticationEntryPoint((request, response, authException) -> {
//                        System.out.println("==========authException =====" + authException);
//                        response.sendRedirect("/u/login?return_to=" + request.getServletPath());
//                    })
//                    .realm("oauth/demo")
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

    @Configuration
    protected static class Stuff {

        @Autowired
        private ClientDetailsService clientDetailsService;

        @Autowired
        private TokenStore tokenStore;

        @Bean
        public ApprovalStore approvalStore() throws Exception {
            TokenApprovalStore store = new TokenApprovalStore();
            store.setTokenStore(tokenStore);
            return store;
        }

        @Bean
        @Lazy
        @Scope(proxyMode = ScopedProxyMode.TARGET_CLASS)
        public CustomUserApprovalHandler userApprovalHandler() throws Exception {
            CustomUserApprovalHandler handler = new CustomUserApprovalHandler();
            handler.setApprovalStore(approvalStore());
            handler.setRequestFactory(new DefaultOAuth2RequestFactory(clientDetailsService));
            handler.setClientDetailsService(clientDetailsService);
            handler.setUseApprovalStore(true);
            return handler;
        }
    }


}
