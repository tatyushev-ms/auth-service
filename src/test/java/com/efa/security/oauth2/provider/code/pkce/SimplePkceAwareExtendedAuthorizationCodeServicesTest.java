package com.efa.security.oauth2.provider.code.pkce;

import com.efa.LazyObjectFactory;
import com.efa.ProxyCreator;
import com.efa.security.oauth2.provider.RequestTokenFactory;
import com.efa.security.oauth2.provider.code.AuthorizationCodeGenerator;
import com.efa.security.oauth2.provider.code.AuthorizationCodeStore;
import com.efa.security.oauth2.provider.code.InMemoryAuthorizationCodeStore;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;

@DisplayName("SimplePkceAwareExtendedAuthorizationCodeServices tests")
class SimplePkceAwareExtendedAuthorizationCodeServicesTest {
    
    private final Authentication userAuthentication = new UsernamePasswordAuthenticationToken("koala", "kangaroo",
            AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
    
    private final String clientId = "qwerty";
    private final String scope = "profile";
    private final String resource = "wombat";
    
    private final LazyObjectFactory<ClientDetails> clientHolder = new LazyObjectFactory<>();
    private final ClientDetails client = ProxyCreator.getProxy(ClientDetails.class, clientHolder);
    
    private final ClientDetailsService clientDetailsService = clientId -> client;
    
    private final OAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
    
    private final Map<String, String> parameters = new HashMap<>();
    
    private final TestAuthorizationCodeGenerator authorizationCodeGenerator = new TestAuthorizationCodeGenerator();
    private final AuthorizationCodeStore<OAuth2Authentication, PkceAwareAuthorizationCodeStoreItem<OAuth2Authentication>> authorizationCodeStore = new InMemoryAuthorizationCodeStore<>();
    
    private final SimplePkceAwareExtendedAuthorizationCodeServices services = new SimplePkceAwareExtendedAuthorizationCodeServices(
            authorizationCodeGenerator, authorizationCodeStore, clientDetailsService);
    
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
        @DisplayName("Returns an error for a public client")
        void shouldReturnErrorForPublicClient() {
            //given
            clientHolder.setObject(publicClient());
            
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            //then
            assertThrows(InvalidRequestException.class, () ->
                            services.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication)),
                    "Should throw InvalidRequestException because of client is public");
        }
        
        @Test
        @DisplayName("Creates an authorization code")
        void shouldCreateAuthorizationCode() {
            //given
            final String expectedCode = "echidna";
            
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            final OAuth2Authentication authentication = new OAuth2Authentication(storedOAuth2Request, userAuthentication);
            
            authorizationCodeGenerator.willReturn(expectedCode);
            
            //when
            final String code = services.createAuthorizationCode(authentication);
            
            //then
            assertThat(code, is(equalTo(expectedCode)));
        }
        
        @Test
        @DisplayName("Returns the same instance of an authentication")
        void shouldReturnTheSameInstanceOfAuthentication() {
            //given
            final String authorizationCode = "emu";
            
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            final OAuth2Authentication expectedAuthentication = new OAuth2Authentication(storedOAuth2Request, userAuthentication);
            
            authorizationCodeGenerator.willReturn(authorizationCode);
            
            final String code = services.createAuthorizationCode(expectedAuthentication);
            parameters.put(OAuth2ParameterNames.CODE, code);
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2Authentication actualAuthentication = services.consumeTokenRequest(tokenRequest);
            
            //then
            assertThat(actualAuthentication, is(equalTo(expectedAuthentication)));
        }
        
        @Test
        @DisplayName("Handles non existing code")
        void shouldHandleNonExistingCode() {
            //given
            final String authorizationCode = "echidna";
            
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            parameters.put(OAuth2ParameterNames.CODE, authorizationCode);
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //then
            assertThrows(InvalidGrantException.class, () -> services.consumeTokenRequest(tokenRequest));
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
        @DisplayName("Returns an error when a client doesn't send \"code_challenge\"")
        void shouldReturnErrorWhenClientDoesNotSendCodeChallenge() {
            //given
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            
            //then
            final InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                            services.createAuthorizationCode(new OAuth2Authentication(storedOAuth2Request, userAuthentication)),
                    "Should throw InvalidRequestException because of client didn't send code_challenge");
            assertThat(exception.getMessage(), is(equalTo("A code challenge must be supplied.")));
        }
        
        @Test
        @DisplayName("Creates an authorization code")
        void shouldCreateAuthorizationCode() {
            //given
            final String expectedCode = "echidna";
            
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
            parameters.put(PkceParameterNames.CODE_CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            final OAuth2Authentication authentication = new OAuth2Authentication(storedOAuth2Request, userAuthentication);
            
            authorizationCodeGenerator.willReturn(expectedCode);
            
            //when
            final String code = services.createAuthorizationCode(authentication);
            
            //then
            assertThat(code, is(equalTo(expectedCode)));
        }
        
        @Test
        @DisplayName("Returns the same instance of an authentication")
        void shouldReturnTheSameInstanceOfAuthentication() {
            //given
            final String authorizationCode = "echidna";
            
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
            parameters.put(PkceParameterNames.CODE_CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
            
            final OAuth2Request storedOAuth2Request = RequestTokenFactory.createCorrectOAuth2Request(parameters, client, true);
            final OAuth2Authentication expectedAuthentication = new OAuth2Authentication(storedOAuth2Request, userAuthentication);
            
            authorizationCodeGenerator.willReturn(authorizationCode);
            
            final String code = services.createAuthorizationCode(expectedAuthentication);
            parameters.put(OAuth2ParameterNames.CODE, code);
            parameters.put(PkceParameterNames.CODE_VERIFIER, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //when
            final OAuth2Authentication actualAuthentication = services.consumeTokenRequest(tokenRequest);
            
            //then
            assertThat(actualAuthentication, is(equalTo(expectedAuthentication)));
        }
        
        @Test
        @DisplayName("Handles non existing code")
        void shouldHandleNonExistingCode() {
            //given
            final String authorizationCode = "echidna";
            
            parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.put(OAuth2ParameterNames.SCOPE, scope);
            parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
            parameters.put(PkceParameterNames.CODE_CHALLENGE, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
            parameters.put(OAuth2ParameterNames.CODE, authorizationCode);
            parameters.put(PkceParameterNames.CODE_VERIFIER, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
            
            final TokenRequest tokenRequest = requestFactory.createTokenRequest(parameters, client);
            
            //then
            assertThrows(InvalidGrantException.class, () -> services.consumeTokenRequest(tokenRequest));
        }
        
    }
    
    @NoArgsConstructor
    @AllArgsConstructor
    private static class TestAuthorizationCodeGenerator implements AuthorizationCodeGenerator {
    
        private String returnedValue;
    
        void willReturn(String returnedValue) {
            this.returnedValue = returnedValue;
        }
    
        @Override
        public String createAuthorizationCode(OAuth2Authentication authentication) {
            return returnedValue;
        }
    
    }
    
}
