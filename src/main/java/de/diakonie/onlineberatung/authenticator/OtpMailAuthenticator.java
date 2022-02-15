package de.diakonie.onlineberatung.authenticator;

import static de.diakonie.onlineberatung.authenticator.OtpParameterAuthenticator.extractDecodedOtpParam;
import static de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType.EMAIL;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import de.diakonie.onlineberatung.credential.MailOtpCredentialModel;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import de.diakonie.onlineberatung.otp.OtpMailSender;
import de.diakonie.onlineberatung.otp.OtpService;
import java.util.List;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

public class OtpMailAuthenticator extends AbstractDirectGrantAuthenticator {

  private static final Logger logger = Logger.getLogger(OtpMailAuthenticator.class);

  private final OtpService otpService;
  private final OtpMailSender mailSender;

  public OtpMailAuthenticator(OtpService otpService, OtpMailSender mailSender) {
    this.otpService = otpService;
    this.mailSender = mailSender;
  }

  @Override
  public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel,
      UserModel userModel) {
    var mailOtpCredentialModel = otpService.getCredential(keycloakSession, realmModel, userModel);
    return nonNull(mailOtpCredentialModel) && mailOtpCredentialModel.getOtp().isActive();
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    var user = context.getUser();
    var realm = context.getRealm();
    var credentialModel = otpService.getCredential(context.getSession(), realm, user);

    if (isNull(credentialModel)) {
      context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
          errorResponse(Status.UNAUTHORIZED.getStatusCode(),
              "invalid_grant", "No corresponding code"));
      return;
    }

    var otpOfRequest = extractDecodedOtpParam(context);
    if (isNull(otpOfRequest) || otpOfRequest.isBlank()) {
      sendOtpMail(context, user, credentialModel);
      return;
    }

    validateOtp(context, user, otpOfRequest, credentialModel);
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

  }

  private void sendOtpMail(AuthenticationFlowContext context, UserModel user,
      MailOtpCredentialModel credentialModel) {
    var realm = context.getRealm();
    var emailAddress = user.getEmail();

    try {
      var otp = otpService.createOtp(emailAddress, true);
      otpService.update(credentialModel, realm, user, otp);
      mailSender.sendOtpCode(otp, context.getSession(), user, emailAddress);

      var challengeResponse = new Challenge().error("invalid_grant")
          .errorDescription("Missing totp").otpType(EMAIL);
      context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
          Response.status(Status.BAD_REQUEST).entity(challengeResponse)
              .type(MediaType.APPLICATION_JSON_TYPE).build());
    } catch (Exception e) {
      otpService.invalidate(credentialModel, realm, user);
      logger.error("failed to send otp mail", e);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR,
          errorResponse(Status.INTERNAL_SERVER_ERROR.getStatusCode(),
              "internal_error", "failed to send otp email"));
    }
  }

  private void validateOtp(AuthenticationFlowContext context, UserModel user, String otpRequest,
      MailOtpCredentialModel credentialModel) {
    var realm = context.getRealm();
    switch (otpService.validate(otpRequest, credentialModel, realm, user)) {
      case NOT_PRESENT:
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
            errorResponse(Status.UNAUTHORIZED.getStatusCode(),
                "invalid_grant", "No corresponding code"));
        break;
      case EXPIRED:
        context.failure(AuthenticationFlowError.EXPIRED_CODE,
            errorResponse(Status.UNAUTHORIZED.getStatusCode(),
                "invalid_grant", "Code expired"));
        break;
      case INVALID:
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
            errorResponse(Status.UNAUTHORIZED.getStatusCode(),
                "invalid_grant", "Invalid code"));
        break;
      case TOO_MANY_FAILED_ATTEMPTS:
        context.failure(AuthenticationFlowError.ACCESS_DENIED,
            errorResponse(Status.TOO_MANY_REQUESTS.getStatusCode(),
                "invalid_grant", "Maximal number of failed attempts reached"));
        break;
      case VALID:
        context.success();
        break;
      default:
        context.failure(AuthenticationFlowError.INTERNAL_ERROR,
            errorResponse(Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                "internal_error", "failed to validate code"));
    }
  }

  @Override
  public String getDisplayType() {
    return null;
  }

  @Override
  public String getReferenceCategory() {
    return "otp";
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return new Requirement[0];
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return null;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return null;
  }

  @Override
  public String getId() {
    return null;
  }
}
