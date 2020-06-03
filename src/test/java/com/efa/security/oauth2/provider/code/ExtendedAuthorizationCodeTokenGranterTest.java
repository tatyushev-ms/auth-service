package com.efa.security.oauth2.provider.code;

import com.efa.LazyObjectFactory;
import com.efa.ProxyCreator;
import com.efa.security.oauth2.provider.RequestTokenFactory;
import com.efa.security.oauth2.provider.code.pkce.SimplePkceAwareExtendedAuthorizationCodeServices;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("ExtendedAuthorizationCodeTokenGranter tests")
class ExtendedAuthorizationCodeTokenGranterTest {
    
    private final Authentication userAuthentication = new UsernamePasswordAuthenticationToken("koala", "kangaroo",
            AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
    
    private final DefaultTokenServices providerTokenServices = new DefaultTokenServices();
    
    private final String clientId = "qwerty";
    private final String scope = "profile";
    private final String resource = "wombat";
    
    private final LazyObjectFactory<ClientDetails> clientHolder = new LazyObjectFactory<>();
    private final ClientDetails client = ProxyCreator.getProxy(ClientDetails.class, clientHolder);
    
    private final ClientDetailsService clientDetailsService = clientId -> client;
    
    private final ExtendedAuthorizationCodeServices extendedAuthorizationCodeServices = new SimplePkceAwareExtendedAuthorizationCodeServices(
            new RandomValueAuthorizationCodeGenerator(), new InMemoryAuthorizationCodeStore<>(), clientDetailsService);
    
    private final OAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
    
    final ExtendedAuthorizationCodeTokenGranter granter = new ExtendedAuthorizationCodeTokenGranter(
            providerTokenServices, extendedAuthorizationCodeServices, clientDetailsService, requestFactory);
    
    private final Map<String, String> parameters = new HashMap<>();
    
    public ExtendedAuthorizationCodeTokenGranterTest() {
        providerTokenServices.setTokenStore(new InMemoryTokenStore());
    }
    
    @BeforeEach
    void setUp() {
        parameters.clear();
    }
    
    private BaseClientDetails publicClient() {
        final BaseClientDetails result = new BaseClientDetails(clientId, resource, scope, AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), "ROLE_CLIENT");
        result.setAutoApproveScopes(Collections.singleton(scope));
        return result;
    }
    
    private BaseClientDetails privateClient() {
        final BaseClientDetails result = publicClient();
        result.setClientSecret("spring");
        return result;
    }
    
    @Nested
    @DisplayName("Handles non-PKCE flow (it is the usual authorization_code flow; a client is private)")
    class NonPkceFlow {
        
        @BeforeEach
        void setUp() {
            clientHolder.setObject(privateClient());
        }
        
        @Test
        @DisplayName("Grants an access token")
        void shouldGrantAccessToken() {
            //given
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.putAll(storedOAuth2Request.getRequestParameters());
            parameters.put(OAuth2ParameterNames.CODE, code);
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Authentication oAuth2Authentication = providerTokenServices.loadAuthentication(token.getValue());
            assertThat(oAuth2Authentication.isAuthenticated(), is(true));
        }
        
        @Test
        @DisplayName("Preserves arbitrary parameters")
        void shouldPreserveArbitraryParameters() {
            //given
            parameters.put("foo", "bar");
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.put(OAuth2ParameterNames.CODE, code);
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Request finalRequest = providerTokenServices.loadAuthentication(token.getValue()).getOAuth2Request();
            assertThat(finalRequest.getRequestParameters().get(OAuth2ParameterNames.CODE), is(equalTo(code)));
            assertThat(finalRequest.getRequestParameters().get("foo"), is(notNullValue()));
            assertThat(finalRequest.getRequestParameters().get("foo"), is(equalTo("bar")));
        }
        
        @Test
        @DisplayName("Preserves an authorization request")
        void shouldPreserveAuthorizationRequest() {
            //given
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.put(OAuth2ParameterNames.CODE, code);
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Request finalRequest = providerTokenServices.loadAuthentication(token.getValue()).getOAuth2Request();
            assertThat(finalRequest.getScope(), contains(scope));
            assertThat(finalRequest.getResourceIds(), contains(resource));
            assertThat(finalRequest.isApproved(), is(true));
        }
        
        @Test
        @DisplayName("Doesn't grant scopes that are not granted to a client when they are asked on an authorization code request")
        void shouldNotGrantScopesThatAreNotGrantedToClientWhenTheyAreAskedOnAuthorizationCodeRequest() {
            //given
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope + " write");
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.put(OAuth2ParameterNames.CODE, code);
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Request finalRequest = providerTokenServices.loadAuthentication(token.getValue()).getOAuth2Request();
            assertThat(finalRequest.getScope(), contains(scope));
            assertThat(finalRequest.getResourceIds(), contains(resource));
            assertThat(finalRequest.isApproved(), is(true));
        }
        
        @Test
        @DisplayName("Doesn't grant scopes that are not granted to a client when they are asked on a token request")
        void shouldNotGrantScopesThatAreNotGrantedToClientWhenTheyAreAskedOnTokenRequest() {
            //given
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.put(OAuth2ParameterNames.CODE, code);
            parameters.put(OAuth2ParameterNames.SCOPE, scope + " write");
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Request finalRequest = providerTokenServices.loadAuthentication(token.getValue()).getOAuth2Request();
            assertThat(finalRequest.getScope(), contains(scope));
            assertThat(finalRequest.getResourceIds(), contains(resource));
            assertThat(finalRequest.isApproved(), is(true));
        }
        
        @Test
        @DisplayName("Grants an access token to a client with no authorities")
        void shouldGrantAccessTokenToClientWithNoAuthorities() {
            //given
            ((BaseClientDetails) clientHolder.getObject()).setAuthorities(Collections.emptySet());
            
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.put(OAuth2ParameterNames.CODE, code);
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Authentication oAuth2Authentication = providerTokenServices.loadAuthentication(token.getValue());
            assertThat(oAuth2Authentication.isAuthenticated(), is(true));
            assertThat(oAuth2Authentication.getOAuth2Request().getAuthorities(), is(empty()));
        }
        
        @Test
        @DisplayName("Checks \"redirect_uri\" values")
        void shouldCheckRedirectUriValues() {
            //given
            ((BaseClientDetails) clientHolder.getObject()).setRegisteredRedirectUri(Collections.singleton("https://redirectMe"));
            
            parameters.put(OAuth2ParameterNames.REDIRECT_URI, "https://redirectMe");
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.put(OAuth2ParameterNames.CODE, code);
            
            //when
            parameters.remove(OAuth2ParameterNames.REDIRECT_URI);
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //then
            assertThrows(RedirectMismatchException.class,
                    () -> granter.getOAuth2Authentication(client, tokenRequest),
                    "Should throw RedirectMismatchException because of null redirect_uri in authorizationRequest");
        }
        
    }
    
    @Nested
    @DisplayName("Handles PKCE flow (a client is public)")
    class PkceFlow {
        
        @BeforeEach
        void setUp() {
            clientHolder.setObject(publicClient());
        }
        
        @Test
        @DisplayName("Grants an access token when \"code_challenge_method\" is \"plain\"")
        void shouldGrantAccessTokenWhenCodeChallengeMethodIsPlain() {
            //given
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "plain");
            parameters.put(PkceParameterNames.CODE_CHALLENGE, "platypus");
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.putAll(storedOAuth2Request.getRequestParameters());
            parameters.put(OAuth2ParameterNames.CODE, code);
            parameters.put(PkceParameterNames.CODE_VERIFIER, "platypus");
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Authentication oAuth2Authentication = providerTokenServices.loadAuthentication(token.getValue());
            assertThat(oAuth2Authentication.isAuthenticated(), is(true));
        }
        
        @Test
        @DisplayName("Grants an access token when \"code_challenge_method\" is \"S256\"")
        void shouldGrantAccessTokenWhenCodeChallengeMethodIsS256() {
            //given
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
            parameters.put(PkceParameterNames.CODE_CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.putAll(storedOAuth2Request.getRequestParameters());
            parameters.put(OAuth2ParameterNames.CODE, code);
            parameters.put(PkceParameterNames.CODE_VERIFIER, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Authentication oAuth2Authentication = providerTokenServices.loadAuthentication(token.getValue());
            assertThat(oAuth2Authentication.isAuthenticated(), is(true));
        }
        
        @Test
        @DisplayName("Treats an absence of \"code_challenge_method\" as \"plain\"")
        void shouldTreatAbsenceOfChallengeMethodAsPlain() {
            //given
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            parameters.put(PkceParameterNames.CODE_CHALLENGE, "platypus");
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.putAll(storedOAuth2Request.getRequestParameters());
            parameters.put(OAuth2ParameterNames.CODE, code);
            parameters.put(PkceParameterNames.CODE_VERIFIER, "platypus");
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Authentication oAuth2Authentication = providerTokenServices.loadAuthentication(token.getValue());
            assertThat(oAuth2Authentication.isAuthenticated(), is(true));
        }
        
        @Test
        @DisplayName("Preserves arbitrary parameters")
        void shouldPreserveArbitraryParameters() {
            //given
            parameters.put("foo", "bar");
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
            parameters.put(PkceParameterNames.CODE_CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.put(OAuth2ParameterNames.CODE, code);
            parameters.put(PkceParameterNames.CODE_VERIFIER, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Request finalRequest = providerTokenServices.loadAuthentication(token.getValue()).getOAuth2Request();
            assertThat(finalRequest.getRequestParameters().get(OAuth2ParameterNames.CODE), is(equalTo(code)));
            assertThat(finalRequest.getRequestParameters().get("foo"), is(notNullValue()));
            assertThat(finalRequest.getRequestParameters().get("foo"), is(equalTo("bar")));
        }
        
        @Test
        @DisplayName("Preserves an authorization request")
        void shouldPreserveAuthorizationRequest() {
            //given
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
            parameters.put(PkceParameterNames.CODE_CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.put(OAuth2ParameterNames.CODE, code);
            parameters.put(PkceParameterNames.CODE_VERIFIER, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Request finalRequest = providerTokenServices.loadAuthentication(token.getValue()).getOAuth2Request();
            assertThat(finalRequest.getScope(), contains(scope));
            assertThat(finalRequest.getResourceIds(), contains(resource));
            assertThat(finalRequest.isApproved(), is(true));
        }
        
        @Test
        @DisplayName("Doesn't grant scopes that are not granted to a client when they are asked on an authorization code request")
        void shouldNotGrantScopesThatAreNotGrantedToClientWhenTheyAreAskedOnAuthorizationCodeRequest() {
            //given
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope + " write");
            parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
            parameters.put(PkceParameterNames.CODE_CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.put(OAuth2ParameterNames.CODE, code);
            parameters.put(PkceParameterNames.CODE_VERIFIER, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Request finalRequest = providerTokenServices.loadAuthentication(token.getValue()).getOAuth2Request();
            assertThat(finalRequest.getScope(), contains(scope));
            assertThat(finalRequest.getResourceIds(), contains(resource));
            assertThat(finalRequest.isApproved(), is(true));
        }
        
        @Test
        @DisplayName("Doesn't grant scopes that are not granted to a client when they are asked on a token request")
        void shouldNotGrantScopesThatAreNotGrantedToClientWhenTheyAreAskedOnTokenRequest() {
            //given
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
            parameters.put(PkceParameterNames.CODE_CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.put(OAuth2ParameterNames.CODE, code);
            parameters.put(OAuth2ParameterNames.SCOPE, scope + " write");
            parameters.put(PkceParameterNames.CODE_VERIFIER, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Request finalRequest = providerTokenServices.loadAuthentication(token.getValue()).getOAuth2Request();
            assertThat(finalRequest.getScope(), contains(scope));
            assertThat(finalRequest.getResourceIds(), contains(resource));
            assertThat(finalRequest.isApproved(), is(true));
        }
        
        @Test
        @DisplayName("Grants an access token to a client with no authorities")
        void shouldGrantAccessTokenToClientWithNoAuthorities() {
            //given
            ((BaseClientDetails) clientHolder.getObject()).setAuthorities(Collections.emptySet());
            
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
            parameters.put(PkceParameterNames.CODE_CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.put(OAuth2ParameterNames.CODE, code);
            parameters.put(PkceParameterNames.CODE_VERIFIER, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2AccessToken token = granter.grant(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), tokenRequest);
            
            //then
            final OAuth2Authentication oAuth2Authentication = providerTokenServices.loadAuthentication(token.getValue());
            assertThat(oAuth2Authentication.isAuthenticated(), is(true));
            assertThat(oAuth2Authentication.getOAuth2Request().getAuthorities(), is(empty()));
        }
        
        @Test
        @DisplayName("Checks \"redirect_uri\" values")
        void shouldCheckRedirectUriValues() {
            //given
            ((BaseClientDetails) clientHolder.getObject()).setRegisteredRedirectUri(Collections.singleton("https://redirectMe"));
            
            parameters.put(OAuth2ParameterNames.REDIRECT_URI, "https://redirectMe");
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
            parameters.put(PkceParameterNames.CODE_CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            final String code = extendedAuthorizationCodeServices.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication));
            parameters.put(OAuth2ParameterNames.CODE, code);
            parameters.put(PkceParameterNames.CODE_VERIFIER, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
            
            //when
            parameters.remove(OAuth2ParameterNames.REDIRECT_URI);
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //then
            assertThrows(RedirectMismatchException.class,
                    () -> granter.getOAuth2Authentication(client, tokenRequest),
                    "Should throw RedirectMismatchException because of null redirect_uri in authorizationRequest");
        }
        
    }
    
}
