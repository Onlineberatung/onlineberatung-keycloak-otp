package de.diakonie.onlineberatung.otp;

import org.keycloak.authentication.AuthenticationFlowContext;

public interface OtpAuthenticator {

  void authenticate(AuthenticationFlowContext context);

}
