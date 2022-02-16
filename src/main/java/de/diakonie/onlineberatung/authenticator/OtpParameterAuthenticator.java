package de.diakonie.onlineberatung.authenticator;

import static de.diakonie.onlineberatung.authenticator.MultiOtpAuthenticator.extractDecodedOtpParam;
import static de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType.APP;

import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import de.diakonie.onlineberatung.otp.OtpAuthenticator;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.credential.OTPCredentialModel;

public class OtpParameterAuthenticator implements OtpAuthenticator {

  @Override
  public boolean isConfigured(AuthenticationFlowContext context) {
    var realm = context.getRealm();
    var user = context.getUser();
    return context.getSession().userCredentialManager()
        .isConfiguredFor(realm, user, OTPCredentialModel.TYPE);

  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String otpOfRequest = extractDecodedOtpParam(context);
    if (otpOfRequest == null) {
      Challenge challengeResponse = new Challenge().error("invalid_grant")
          .errorDescription("Missing totp").otpType(APP);
      context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
          Response.status(Status.BAD_REQUEST).entity(challengeResponse)
              .type(MediaType.APPLICATION_JSON_TYPE).build());
      return;
    }
    context.success();
  }
}