package com.efa;

import lombok.extern.apachecommons.CommonsLog;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Base64Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static com.efa.ParameterizedTypeReferenceInstance.STRING_STRING_MAP;

@Disabled
@CommonsLog
public class AuthServiceApplicationTests {
    
    private RestTemplate restTemplate;
    private int port;
    
    @BeforeEach
    public void setUp() {
        restTemplate = new RestTemplate();
        
        ConfigurableApplicationContext applicationContext = SpringApplication.run(AuthServiceApplication.class);
        port = applicationContext.getEnvironment().getProperty("local.server.port", Integer.class, 8080);
    }
    
    @Test
    public void generateToken() {
        String client = "democlient";
        String clientSecret = "demopassword";
        
        URI uri = URI.create("http://localhost:" + port + "/uaa/oauth/token");
        
        LinkedMultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", client);
        requestBody.add("client_secret", clientSecret);
        requestBody.add("scope", "openid");
        requestBody.add("grant_type", "password");
        requestBody.add("username", "john");
        requestBody.add("password", "doe");
        
        String token = Base64Utils.encodeToString((client + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        
        RequestEntity<LinkedMultiValueMap<String, String>> requestEntity = RequestEntity.post(uri)
                .accept(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Basic " + token)
                .body(requestBody);
        
        ResponseEntity<Map<String, String>> responseEntity = restTemplate.exchange(requestEntity, STRING_STRING_MAP);
        
        Map<String, String> body = responseEntity.getBody();
        
        log.info("access_token: " + body.get("access_token"));
    }
    
}
