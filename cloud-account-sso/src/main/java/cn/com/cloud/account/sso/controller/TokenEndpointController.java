package cn.com.cloud.account.sso.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.endpoint.AbstractEndpoint;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestValidator;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriUtils;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;

/**
 * @author twg
 * @since 2019/7/8
 */
@Slf4j
@FrameworkEndpoint
public class TokenEndpointController extends AbstractEndpoint {

    private OAuth2RequestFactory oAuth2RequestFactory;
    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private AuthorizationServerEndpointsConfiguration endpointsConfiguration;

    private OAuth2RequestValidator oAuth2RequestValidator = new DefaultOAuth2RequestValidator();

    @PostConstruct
    public void init() {
        oAuth2RequestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
        super.setTokenGranter(endpointsConfiguration.getEndpointsConfigurer().getTokenGranter());
        super.setClientDetailsService(endpointsConfiguration.getEndpointsConfigurer().getClientDetailsService());
    }

    @GetMapping("/login/oauth/authorize")
    public ModelAndView oauthAuthorize(@RequestParam Map<String, String> parameters, HttpServletRequest request, Map<String, Object> model) throws IOException {
        String client_id = request.getParameter(OAuth2Utils.CLIENT_ID);
        if (StringUtils.isEmpty(client_id)) {
            return new ModelAndView("forward:/u/login?return_to=" + UriUtils.encode(request.getServletPath(), Charset.defaultCharset()));
        }
        AuthorizationRequest authorizationRequest = getOAuth2RequestFactory().createAuthorizationRequest(parameters);
        model.put("authorizationRequest", authorizationRequest);
        return new ModelAndView("forward:/oauth/confirm_access", model);
    }


    @RequestMapping("/login/oauth/access_token")
    public ResponseEntity<OAuth2AccessToken> accessToken(Principal principal, @RequestParam
            Map<String, String> parameters) {
        if (!(principal instanceof Authentication)) {
            throw new InsufficientAuthenticationException(
                    "There is no client authentication. Try adding an appropriate authentication filter.");
        }
        String clientId = getClientId(principal);
        ClientDetails authenticatedClient = clientDetailsService.loadClientByClientId(clientId);
        TokenRequest tokenRequest = oAuth2RequestFactory.createTokenRequest(parameters, authenticatedClient);
        if (StringUtils.hasText(clientId)) {
            if (!clientId.equals(tokenRequest.getClientId())) {
                throw new InvalidClientException("Given client ID does not match authenticated client");
            }
        }
        if (authenticatedClient != null) {
            oAuth2RequestValidator.validateScope(tokenRequest, authenticatedClient);
        }
        if (!StringUtils.hasText(tokenRequest.getGrantType())) {
            throw new InvalidRequestException("Missing grant type");
        }
        if (tokenRequest.getGrantType().equals("implicit")) {
            throw new InvalidGrantException("Implicit grant type not supported from token endpoint");
        }
        if (isAuthCodeRequest(parameters)) {
            // The scope was requested or determined during the authorization step
            if (!tokenRequest.getScope().isEmpty()) {
                log.debug("Clearing scope of incoming token request");
                tokenRequest.setScope(Collections.<String>emptySet());
            }
        }

        if (isRefreshTokenRequest(parameters)) {
            // A refresh token has its own default scopes, so we should ignore any added by the factory here.
            tokenRequest.setScope(OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)));
        }

        OAuth2AccessToken token = endpointsConfiguration.getEndpointsConfigurer().getTokenGranter().grant(tokenRequest.getGrantType(), tokenRequest);
        if (token == null) {
            throw new UnsupportedGrantTypeException("Unsupported grant type: " + tokenRequest.getGrantType());
        }
        return getResponse(token);
    }


    protected String getClientId(Principal principal) {
        Authentication client = (Authentication) principal;
        if (!client.isAuthenticated()) {
            throw new InsufficientAuthenticationException("The client is not authenticated.");
        }
        String clientId = client.getName();
        if (client instanceof OAuth2Authentication) {
            // Might be a client and user combined authentication
            clientId = ((OAuth2Authentication) client).getOAuth2Request().getClientId();
        }
        return clientId;
    }

    private boolean isRefreshTokenRequest(Map<String, String> parameters) {
        return "refresh_token".equals(parameters.get("grant_type")) && parameters.get("refresh_token") != null;
    }

    private boolean isAuthCodeRequest(Map<String, String> parameters) {
        return "authorization_code".equals(parameters.get("grant_type")) && parameters.get("code") != null;
    }

    public void setOAuth2RequestValidator(OAuth2RequestValidator oAuth2RequestValidator) {
        this.oAuth2RequestValidator = oAuth2RequestValidator;
    }

    private ResponseEntity<OAuth2AccessToken> getResponse(OAuth2AccessToken accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Cache-Control", "no-store");
        headers.set("Pragma", "no-cache");
        headers.set("Content-Type", "application/json;charset=UTF-8");
        return new ResponseEntity<OAuth2AccessToken>(accessToken, headers, HttpStatus.OK);
    }

    @Override
    public void setTokenGranter(TokenGranter tokenGranter) {
        super.setTokenGranter(endpointsConfiguration.getEndpointsConfigurer().getTokenGranter());
    }
}
