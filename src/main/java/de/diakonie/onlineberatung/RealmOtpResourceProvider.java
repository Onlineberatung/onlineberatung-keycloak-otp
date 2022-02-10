package de.diakonie.onlineberatung;

import static java.lang.Boolean.parseBoolean;
import static java.util.Objects.isNull;

import de.diakonie.onlineberatung.authenticator.SessionAuthenticator;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Error;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpInfoDTO;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpSetupDTO;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Success;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.SuccessWithEmail;
import de.diakonie.onlineberatung.otp.OtpMailSender;
import de.diakonie.onlineberatung.otp.OtpService;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.CredentialValidation;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.utils.CredentialHelper;
import org.keycloak.utils.TotpUtils;

public class RealmOtpResourceProvider implements RealmResourceProvider {

  public static final int KEY_LENGTH = 32;
  public static final String ROLE_REQUIRED = "technical";
  public static final String OTP_CONFIG_ALIAS = "email-otp-config";
  public static final String OTP_MAIL_AUTHENTICATION_ATTRIBUTE = "otp-mail-authentication";

  private static final String MISSING_PARAMETER_ERROR = "invalid_parameter";
  private static final String MISSING_USERNAME_ERROR_DESCRIPTION = "username not found";
  private static final String MISSING_EMAIL_ADDRESS_ERROR_DESCRIPTION = "email address of user not available";
  private final static String FAILED_TO_SENT = "failed to send otp verification email";

  private final KeycloakSession session;
  private final SessionAuthenticator sessionAuthenticator;
  private final OtpService otpService;
  private final OtpMailSender mailSender;

  public RealmOtpResourceProvider(KeycloakSession session, OtpService otpService,
      OtpMailSender mailSender, SessionAuthenticator sessionAuthenticator) {
    this.session = session;
    this.otpService = otpService;
    this.mailSender = mailSender;
    this.sessionAuthenticator = sessionAuthenticator;
  }

  @GET
  @Path("fetch-otp-setup-info/{username}")
  @Produces({MediaType.APPLICATION_JSON})
  public Response getOtpSetupInfo(@PathParam("username") final String username) {
    verifyAuthentication();

    final RealmModel realm = this.session.getContext().getRealm();
    final UserModel user = this.session.users().getUserByUsername(realm, username);

    if (isNull(user)) {
      return Response.status(Status.BAD_REQUEST)
          .entity(new Error().error(MISSING_PARAMETER_ERROR)
              .errorDescription(MISSING_USERNAME_ERROR_DESCRIPTION)).build();
    }

    var otpInfoDTO = new OtpInfoDTO();
    var isApp2FaConfigured = this.session.userCredentialManager()
        .isConfiguredFor(realm, user, OTPCredentialModel.TYPE);
    if (isApp2FaConfigured) {
      otpInfoDTO.setOtpSetup(true);
      otpInfoDTO.setOtpType(OtpType.APP);
      return Response.ok(otpInfoDTO).build();
    }

    var isMail2FaConfigured = parseBoolean(
        user.getFirstAttribute(OTP_MAIL_AUTHENTICATION_ATTRIBUTE));
    if (isMail2FaConfigured) {
      otpInfoDTO.setOtpSetup(true);
      otpInfoDTO.setOtpType(OtpType.EMAIL);
      return Response.ok(otpInfoDTO).build();
    }

    String otpSecret = HmacOTP.generateSecret(KEY_LENGTH);
    otpInfoDTO.setOtpSecret(otpSecret);
    otpInfoDTO.setOtpSecretQrCode(TotpUtils.qrCode(otpSecret, realm, user));
    return Response.ok(otpInfoDTO).build();
  }

  @PUT
  @Path("setup-otp/{username}")
  @Consumes({MediaType.APPLICATION_JSON})
  @Produces({MediaType.APPLICATION_JSON})
  public Response setupOtp(@PathParam("username") final String username, final OtpSetupDTO dto) {
    verifyAuthentication();

    final RealmModel realm = this.session.getContext().getRealm();
    final UserModel user = this.session.users().getUserByUsername(realm, username);

    if (isNull(user)) {
      return Response.status(Status.BAD_REQUEST)
          .entity(new Error().error(MISSING_PARAMETER_ERROR)
              .errorDescription(MISSING_USERNAME_ERROR_DESCRIPTION)).build();
    }

    if (!this.session.userCredentialManager()
        .isConfiguredFor(realm, user, OTPCredentialModel.TYPE)) {

      final var otpCredentialModel = OTPCredentialModel
          .createFromPolicy(realm, dto.getSecret());

      if (!CredentialValidation.validOTP(dto.getInitialCode(), otpCredentialModel,
          realm.getOTPPolicy().getLookAheadWindow())) {
        return Response.status(Status.UNAUTHORIZED)
            .entity(new Error().error("invalid_grant").errorDescription("Invalid otp code"))
            .build();
      }

      CredentialHelper
          .createOTPCredential(this.session, realm, user, dto.getInitialCode(), otpCredentialModel);

      return Response.status(Status.CREATED)
          .entity(new Success().info("OTP credential created")).build();
    }

    return Response.ok(new Success().info("OTP credential is already configured for this User"))
        .build();
  }

  @DELETE
  @Path("delete-otp/{username}")
  @Produces({MediaType.APPLICATION_JSON})
  public Response deleteOtp(@PathParam("username") final String username) {
    verifyAuthentication();

    final RealmModel realm = this.session.getContext().getRealm();
    final UserModel user = this.session.users().getUserByUsername(realm, username);

    if (isNull(user)) {
      return Response.status(Status.BAD_REQUEST).entity(new Error().error(MISSING_PARAMETER_ERROR)
          .errorDescription(MISSING_USERNAME_ERROR_DESCRIPTION)).build();
    }

    deleteAllOtpCredentials(realm, user);

    return Response.ok(new Success().info("OTP credential deleted")).build();
  }

  @PUT
  @Path("send-verification-mail/{username}")
  @Produces({MediaType.APPLICATION_JSON})
  public Response sendVerificationMail(@PathParam("username") final String username,
      final OtpSetupDTO mailSetup) {
    verifyAuthentication();

    final var realm = this.session.getContext().getRealm();
    final var user = this.session.users().getUserByUsername(realm, username);

    if (isNull(user)) {
      return Response.status(Status.BAD_REQUEST).entity(new Error().error(MISSING_PARAMETER_ERROR)
          .errorDescription(MISSING_USERNAME_ERROR_DESCRIPTION)).build();
    }

    var emailAddress = mailSetup.getEmail();
    if (isNull(emailAddress) || emailAddress.isBlank()) {
      return Response.status(Status.BAD_REQUEST).entity(new Error().error(MISSING_PARAMETER_ERROR)
          .errorDescription(MISSING_EMAIL_ADDRESS_ERROR_DESCRIPTION)).build();
    }

    try {
      var authConfig = realm.getAuthenticatorConfigByAlias(OTP_CONFIG_ALIAS);
      var otp = otpService.createOtp(authConfig, username, mailSetup.getEmail());
      mailSender.sendOtpCode(otp, session, user, emailAddress);
    } catch (Exception e) {
      e.printStackTrace();
      otpService.invalidate(username);
      return Response.status(Status.INTERNAL_SERVER_ERROR).entity(new Error().error(FAILED_TO_SENT))
          .build();
    }
    return Response.status(Status.OK).entity(new Success().info("OTP mail sent"))
        .build();
  }

  @POST
  @Path("setup-otp-mail/{username}")
  @Consumes({MediaType.APPLICATION_JSON})
  @Produces({MediaType.APPLICATION_JSON})
  public Response setupOtpMail(@PathParam("username") final String username,
      final OtpSetupDTO mailSetup) {
    verifyAuthentication();

    final var realm = this.session.getContext().getRealm();
    final var user = this.session.users().getUserByUsername(realm, username);

    if (isNull(user)) {
      return Response.status(Status.BAD_REQUEST).entity(new Error().error(MISSING_PARAMETER_ERROR)
          .errorDescription(MISSING_USERNAME_ERROR_DESCRIPTION)).build();
    }

    return verifyInitialMailOtp(mailSetup.getInitialCode(), username, user);
  }

  private void deleteAllOtpCredentials(RealmModel realm, UserModel user) {
    user.setSingleAttribute(OTP_MAIL_AUTHENTICATION_ATTRIBUTE, "false");
    this.session.userCredentialManager().
        getStoredCredentialsByTypeStream(realm, user, OTPCredentialModel.TYPE).
        forEach(credentialModel -> CredentialHelper
            .deleteOTPCredential(this.session, realm, user, credentialModel.getId()));
  }

  private void verifyAuthentication() {
    sessionAuthenticator.authenticate(session);
  }

  @Override
  public Object getResource() {
    return this;
  }

  @Override
  public void close() {
    // Do nothing because it is not needed
  }

  private Response verifyInitialMailOtp(String initialCode, String username, UserModel user) {
    var otp = otpService.get(username);
    var validationResult = otpService.validate(initialCode, username);
    switch (validationResult) {
      case NOT_PRESENT:
        return Response.status(Status.UNAUTHORIZED).entity(
            new Error().error("invalid_grant").errorDescription("No corresponding code")).build();
      case EXPIRED:
        return Response.status(Status.UNAUTHORIZED).entity(
            new Error().error("invalid_grant").errorDescription("Code expired")).build();
      case INVALID:
        return Response.status(Status.UNAUTHORIZED).entity(
            new Error().error("invalid_grant").errorDescription("Invalid code")).build();
      case TOO_MANY_FAILED_ATTEMPTS:
        return Response.status(Status.TOO_MANY_REQUESTS).entity(
            new Error().error("invalid_grant")
                .errorDescription("Maximal number of failed attempts reached")).build();
      case VALID:
        user.setSingleAttribute(OTP_MAIL_AUTHENTICATION_ATTRIBUTE, "true");
        return Response.status(Status.CREATED)
            .entity(new SuccessWithEmail().email(otp.getEmail()).info("OTP setup created"))
            .build();
      default:
        return Response.status(Status.INTERNAL_SERVER_ERROR)
            .entity(new Error().error("invalid_grant").errorDescription("failed to validate code"))
            .build();
    }
  }
}
