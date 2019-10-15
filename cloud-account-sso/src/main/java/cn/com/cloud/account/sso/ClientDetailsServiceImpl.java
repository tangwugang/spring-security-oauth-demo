package cn.com.cloud.account.sso;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @author twg
 * @since 2019/7/5
 */
public class ClientDetailsServiceImpl implements ClientDetailsService {
    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("oauth");
        clientDetails.setClientSecret("oauth");
        Set urlSet = new HashSet(1);
        urlSet.add("http://localhost:8080/tonr2/sparklr/photos");
        clientDetails.setRegisteredRedirectUri(urlSet);
        clientDetails.setAuthorizedGrantTypes(Arrays.asList("authorization_code"));
        return clientDetails;
    }
}
