package de.diakonie.onlineberatung.otp;

import org.keycloak.authentication.AuthenticationFlowContext;

public interface OtpAuthenticator {

  boolean isConfigured(AuthenticationFlowContext context);

  void authenticate(AuthenticationFlowContext context);

}
