package de.diakonie.onlineberatung.authenticator;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class OtpParameterAuthenticator implements Authenticator {

  @Override
  public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
    MultivaluedMap<String, String> inputData = authenticationFlowContext.getHttpRequest().getDecodedFormParameters();
    String otp = inputData.getFirst("otp");
    otp = (otp == null) ? inputData.getFirst("totp") : otp;

    if (otp == null) {
      authenticationFlowContext.failure(
          AuthenticationFlowError.INVALID_CREDENTIALS, Response.status(Status.BAD_REQUEST).entity("{\"otpMissing\": true}").type("application/json").build());
      return;
    }
    authenticationFlowContext.success();
  }

  @Override
  public void action(AuthenticationFlowContext authenticationFlowContext) {
    // Do nothing because it is not needed
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel,
      UserModel userModel) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel,
      UserModel userModel) {
    // Nothing to do here because configuredFor always returns true
  }

  @Override
  public void close() {
    // Do nothing because it is not needed
  }
}