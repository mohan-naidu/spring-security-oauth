package com.baeldung.resource;

import com.baeldung.resource.spring.UserNameValidator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;

@ExtendWith(MockitoExtension.class)
public class UserNameValidatorTest {

  private UserNameValidator userNameValidator;


  @Test
  public void givenEmailAddress_whenValidPreferredName_thenSuccess(){
    userNameValidator = new UserNameValidator();
    Map<String, Object> headers = new HashMap<>();
    headers.put(HttpHeaders.AUTHORIZATION, "Bearer token");
    headers.put("typ", "JWT");
    headers.put("alg", "none");

    Map<String, Object> claims = new HashMap<>();
    claims.put("preferred_username", "john@test.com");

    Jwt jwt = new Jwt("fake-token", Instant.now(), Instant.now().plusSeconds(100), headers, claims);
    Assertions.assertFalse(userNameValidator.validate(jwt).hasErrors());
  }

  @Test
  public void givenEmailAddress_whenInValidPreferredName_thenFailure(){
    userNameValidator = new UserNameValidator();
    Map<String, Object> headers = new HashMap<>();
    headers.put(HttpHeaders.AUTHORIZATION, "Bearer token");
    headers.put("typ", "JWT");
    headers.put("alg", "none");

    Map<String, Object> claims = new HashMap<>();
    claims.put("preferred_username", "mike@other.com");

    Jwt jwt = new Jwt("fake-token", Instant.now(), Instant.now().plusSeconds(100), headers, claims);
    List<OAuth2Error> oAuth2Errors = new ArrayList<>(userNameValidator.validate(jwt).getErrors());
    Assertions.assertEquals(oAuth2Errors.get(0).getErrorCode(), "code 401");
    Assertions.assertEquals(oAuth2Errors.get(0).getDescription(), "unauthorized user");
  }
}
