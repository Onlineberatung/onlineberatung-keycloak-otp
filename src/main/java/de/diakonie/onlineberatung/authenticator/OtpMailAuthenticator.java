package de.diakonie.onlineberatung.authenticator;

import static de.diakonie.onlineberatung.RealmOtpResourceProvider.OTP_MAIL_AUTHENTICATION_ATTRIBUTE;
import static de.diakonie.onlineberatung.authenticator.MultiOtpAuthenticator.extractDecodedOtpParam;
import static de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType.EMAIL;
import static java.lang.Boolean.parseBoolean;
import static java.util.Objects.isNull;
import static org.keycloak.authentication.authenticators.client.ClientAuthUtil.errorResponse;

import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import de.diakonie.onlineberatung.otp.OtpAuthenticator;
import de.diakonie.onlineberatung.otp.OtpMailSender;
import de.diakonie.onlineberatung.otp.OtpService;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.UserModel;

public class OtpMailAuthenticator implements OtpAuthenticator {

  private final OtpService otpService;
  private final OtpMailSender mailSender;

  public OtpMailAuthenticator(OtpService otpService, OtpMailSender mailSender) {
    this.otpService = otpService;
    this.mailSender = mailSender;
  }

  @Override
  public boolean isConfigured(AuthenticationFlowContext context) {
    var user = context.getUser();
    return parseBoolean(user.getFirstAttribute(OTP_MAIL_AUTHENTICATION_ATTRIBUTE));
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    var user = context.getUser();

    var otpOfRequest = extractDecodedOtpParam(context);
    if (isNull(otpOfRequest) || otpOfRequest.isBlank()) {
      sendOtpMail(context, user);
      return;
    }

    validateOtp(context, user.getUsername(), otpOfRequest);
  }

  private void sendOtpMail(AuthenticationFlowContext context, UserModel user) {
    var username = user.getUsername();
    var emailAddress = user.getEmail();

    try {
      var otp = otpService.createOtp(username, emailAddress);
      mailSender.sendOtpCode(otp, context.getSession(), user, emailAddress);

      var challengeResponse = new Challenge().error("invalid_grant")
          .errorDescription("Missing totp").otpType(EMAIL);
      context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
          Response.status(Status.BAD_REQUEST).entity(challengeResponse)
              .type(MediaType.APPLICATION_JSON_TYPE).build());
    } catch (Exception e) {
      e.printStackTrace();
      otpService.invalidate(username);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR,
          errorResponse(Status.INTERNAL_SERVER_ERROR.getStatusCode(),
              "internal_error", "failed to send otp email"));
    }
  }

  private void validateOtp(AuthenticationFlowContext context, String username, String otpRequest) {
    switch (otpService.validate(otpRequest, username)) {
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
}
