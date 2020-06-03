package com.efa;

import com.efa.client.ClientRepository;
import com.efa.client.DemoClientDetailsService;
import com.efa.security.oauth2.config.annotation.web.configuration.JwkSetEndpointConfiguration;
import com.efa.security.oauth2.provider.code.*;
import com.efa.security.oauth2.provider.code.pkce.PkceAwareAuthorizationCodeStoreItem;
import com.efa.security.oauth2.provider.code.pkce.SimplePkceAwareExtendedAuthorizationCodeServices;
import com.efa.security.oauth2.provider.token.JwtIssuerClaimTokenEnhancer;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configuration.ClientDetailsServiceConfiguration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.net.URL;
import java.security.KeyPair;
import java.util.Arrays;

@Import({AuthorizationServerEndpointsConfiguration.class, JwkSetEndpointConfiguration.class})
@Configuration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
    
    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;
    private final KeyPair keyPair;
    private final URL issuerValue;
    
    public AuthorizationServerConfiguration(ClientRepository clientRepository,
                                            @Qualifier("clientDetailsServicePasswordEncoder") PasswordEncoder passwordEncoder,
                                            @Qualifier("jwtJwsKeyPair") KeyPair keyPair,
                                            @Qualifier("jwtIssuerClaimValue") URL issuerValue) {
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
        this.keyPair = keyPair;
        this.issuerValue = issuerValue;
    }
    
    @Override
    public void configure(AuthorizationServerSecurityConfigurer authorizationServerSecurityConfigurer) {
        authorizationServerSecurityConfigurer
                .allowFormAuthenticationForClients()
                .passwordEncoder(passwordEncoder);
    }
    
    @Override
    public void configure(ClientDetailsServiceConfigurer clientDetailsServiceConfigurer) throws Exception {
        clientDetailsServiceConfigurer
                .withClientDetails(new DemoClientDetailsService());
        //.withClientDetails(new SimpleClientDetailsService(clientRepository));
    }
    
    /**
     * Do not worry about {@link ClientDetailsService} (I mean, the order of this method
     * and {@link AuthorizationServerConfiguration#configure(ClientDetailsServiceConfigurer)}).
     * You will get right instance because of {@link ClientDetailsServiceConfiguration} (Btw, because of
     * {@link ClientDetailsServiceConfiguration} you must not make your {@link ClientDetailsService} a bean).
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer authorizationServerEndpointsConfigurer) {
        final AuthorizationServerTokenServices tokenServices = authorizationServerEndpointsConfigurer.getTokenServices();
        final ClientDetailsService clientDetailsService = authorizationServerEndpointsConfigurer.getClientDetailsService();
        final OAuth2RequestFactory requestFactory = authorizationServerEndpointsConfigurer.getOAuth2RequestFactory();
        
        final ExtendedAuthorizationCodeServices extendedAuthorizationCodeServices = extendedAuthorizationCodeServices(clientDetailsService);
        
        authorizationServerEndpointsConfigurer
                .authorizationCodeServices(new ExtendedAuthorizationCodeServicesAdapter(extendedAuthorizationCodeServices))
                .accessTokenConverter(accessTokenConverter())
                .tokenEnhancer(tokenEnhancer())
                .tokenStore(tokenStore())
                .tokenGranter(tokenGranter(tokenServices, extendedAuthorizationCodeServices, clientDetailsService, requestFactory));
    }
    
    private TokenEnhancer tokenEnhancer() {
        final TokenEnhancerChain result = new TokenEnhancerChain();
        result.setTokenEnhancers(Arrays.asList(new JwtIssuerClaimTokenEnhancer(issuerValue), new JwtAccountNumberClaimTokenEnhancer(), accessTokenConverter()));
        return result;
    }
    
    @Bean
    JwtAccessTokenConverter accessTokenConverter() {
        final JwtAccessTokenConverter result = new JwtAccessTokenConverter();
        result.setKeyPair(keyPair);
        return result;
    }
    
    @Bean
    TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }
    
    /**
     * Adds only an authorization code token granter.
     * If you need other token granters, use {@link CompositeTokenGranter}. For details
     * see {@link AuthorizationServerEndpointsConfigurer}#getDefaultTokenGranters()
     */
    private TokenGranter tokenGranter(AuthorizationServerTokenServices tokenServices,
                                      ExtendedAuthorizationCodeServices extendedAuthorizationCodeServices,
                                      ClientDetailsService clientDetailsService,
                                      OAuth2RequestFactory requestFactory) {
        return new ExtendedAuthorizationCodeTokenGranter(tokenServices, extendedAuthorizationCodeServices, clientDetailsService, requestFactory);
    }
    
    private ExtendedAuthorizationCodeServices extendedAuthorizationCodeServices(ClientDetailsService clientDetailsService) {
        final AuthorizationCodeGenerator authorizationCodeGenerator = new RandomValueAuthorizationCodeGenerator();
        final var authorizationCodeStore = new InMemoryAuthorizationCodeStore<OAuth2Authentication, PkceAwareAuthorizationCodeStoreItem<OAuth2Authentication>>();
        return new SimplePkceAwareExtendedAuthorizationCodeServices(authorizationCodeGenerator, authorizationCodeStore, clientDetailsService);
    }
    
}
