package com.baeldung.resource.spring;

import java.util.Map;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class UserNameValidator implements OAuth2TokenValidator<Jwt> {
  OAuth2Error error = new OAuth2Error("code 401", "unauthorized user", null);

  @Override
  public OAuth2TokenValidatorResult validate(Jwt jwt) {
    Map<String, Object> claims=  jwt.getClaims();
    if (claims.containsKey("preferred_username")) {
      String emailAddress = (String) claims.get("preferred_username");
      if (isEmailBelongToValidDomain(emailAddress)){
        return OAuth2TokenValidatorResult.success();
      }
    }
      return OAuth2TokenValidatorResult.failure(error);
  }

  public boolean isEmailBelongToValidDomain(String email) {
    return email.endsWith("@test.com");
  }
}
