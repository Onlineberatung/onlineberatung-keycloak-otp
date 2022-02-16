package de.diakonie.onlineberatung;

import static de.diakonie.onlineberatung.credential.MailOtpCredentialModel.INVALIDATED;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import de.diakonie.onlineberatung.authenticator.SessionAuthenticator;
import de.diakonie.onlineberatung.credential.CredentialContext;
import de.diakonie.onlineberatung.credential.CredentialService;
import de.diakonie.onlineberatung.credential.MailOtpCredentialModel;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Error;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpInfoDTO;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpSetupDTO;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Success;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.SuccessWithEmail;
import de.diakonie.onlineberatung.otp.Otp;
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
import org.jboss.logging.Logger;
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

  private static final Logger logger = Logger.getLogger(RealmOtpResourceProvider.class);
  private static final String MISSING_PARAMETER_ERROR = "invalid_parameter";
  private static final String ALREADY_ACTIVE = "mail otp credentials are already configured";
  private static final String MISSING_CREDENTIAL_CONFIG = "no mail otp credentials configured";
  private static final String MISSING_USERNAME_ERROR_DESCRIPTION = "username not found";
  private static final String MISSING_EMAIL_ADDRESS_ERROR_DESCRIPTION = "email address of user not available";
  private final static String FAILED_TO_SENT = "failed to send otp verification email";

  private final KeycloakSession session;
  private final SessionAuthenticator sessionAuthenticator;
  private final OtpService otpService;
  private final OtpMailSender mailSender;
  private final CredentialService mailCredentialService;

  public RealmOtpResourceProvider(KeycloakSession session, OtpService otpService,
      OtpMailSender mailSender, SessionAuthenticator sessionAuthenticator,
      CredentialService mailCredentialService) {
    this.session = session;
    this.otpService = otpService;
    this.mailSender = mailSender;
    this.sessionAuthenticator = sessionAuthenticator;
    this.mailCredentialService = mailCredentialService;
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

    var credential = mailCredentialService.getCredential(new CredentialContext(session, realm, user));
    var isMail2FaConfigured = nonNull(credential) && credential.isActive();
    if (isMail2FaConfigured) {
      otpInfoDTO.setOtpSetup(true);
      otpInfoDTO.setOtpType(OtpType.EMAIL);
      return Response.ok(otpInfoDTO).build();
    }

    String otpSecret = HmacOTP.generateSecret(KEY_LENGTH);
    otpInfoDTO.setOtpSetup(false);
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

    return Response.ok(new Success().info("OTP credential is already configured for this user"))
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

    var context = new CredentialContext(session, realm, user);
    var otp = otpService.createOtp(emailAddress);
    return verifyAndSendMail(context, otp);
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

    var context = new CredentialContext(session, realm, user);
    try {
      return verifyMailSetup(mailSetup.getInitialCode(), context);
    } catch (Exception e) {
      logger.error("failed to verify mail setup", e);
      return Response.status(Status.INTERNAL_SERVER_ERROR)
          .entity(new Error().error("internal_error").errorDescription("failed to validate code"))
          .build();
    }
  }

  private void deleteAllOtpCredentials(RealmModel realm, UserModel user) {
    this.session.userCredentialManager().
        getStoredCredentialsByTypeStream(realm, user, OTPCredentialModel.TYPE)
        .forEach(credentialModel -> CredentialHelper
            .deleteOTPCredential(this.session, realm, user, credentialModel.getId()));
    this.mailCredentialService.deleteCredential(new CredentialContext(session, realm, user));
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

  private Response verifyAndSendMail(CredentialContext context, Otp otp) {
    MailOtpCredentialModel credentialModel = null;
    try {
      credentialModel = mailCredentialService.getCredential(context);
      if (isNull(credentialModel)) {
        credentialModel = mailCredentialService.createCredential(otp, context);
      } else if (credentialModel.isActive()) {
        return Response.status(Status.CONFLICT).entity(new Error().error(ALREADY_ACTIVE))
            .build();
      } else {
        mailCredentialService.update(credentialModel.updateFrom(otp), context);
      }
      mailSender.sendOtpCode(otp, context.getSession(), context.getUser(), otp.getEmail());
    } catch (Exception e) {
      if (nonNull(credentialModel)) {
        mailCredentialService.invalidate(credentialModel, context);
      }
      logger.error("failed to send verification mail", e);
      return Response.status(Status.INTERNAL_SERVER_ERROR)
          .entity(new Error().error(FAILED_TO_SENT))
          .build();
    }

    return Response.status(Status.OK).entity(new Success().info("OTP mail sent"))
        .build();
  }

  private Response verifyMailSetup(String initialCode, CredentialContext context) {
    var credentialModel = mailCredentialService.getCredential(context);
    if (isNull(credentialModel)) {
      return Response.status(Status.BAD_REQUEST).entity(
              new Error().error("invalid_grant").errorDescription(MISSING_CREDENTIAL_CONFIG))
          .build();
    }
    if (credentialModel.isActive()) {
      return Response.ok(
          new Success().info("Mail OTP credential is already configured for this User")).build();
    }

    var otp = credentialModel.getOtp();
    var validationResult = otpService.validate(initialCode, otp);

    switch (validationResult) {
      case NOT_PRESENT:
        return Response.status(Status.UNAUTHORIZED).entity(
            new Error().error("invalid_grant").errorDescription("No corresponding code")).build();
      case EXPIRED:
        return Response.status(Status.UNAUTHORIZED).entity(
            new Error().error("invalid_grant").errorDescription("Code expired")).build();
      case INVALID:
        credentialModel.updateFailedVerifications(otp.getFailedVerifications() + 1);
        mailCredentialService.update(credentialModel, context);
        return Response.status(Status.UNAUTHORIZED).entity(
            new Error().error("invalid_grant").errorDescription("Invalid code")).build();
      case TOO_MANY_FAILED_ATTEMPTS:
        return Response.status(Status.TOO_MANY_REQUESTS).entity(
            new Error().error("invalid_grant")
                .errorDescription("Maximal number of failed attempts reached")).build();
      case VALID:
        credentialModel.setActive();
        credentialModel.updateCode(INVALIDATED);
        mailCredentialService.update(credentialModel, context);
        return Response.status(Status.CREATED)
            .entity(new SuccessWithEmail().email(otp.getEmail()).info("OTP setup created"))
            .build();
      default:
        return Response.status(Status.INTERNAL_SERVER_ERROR).entity(
                new Error().error("invalid_grant").errorDescription("failed to validate code"))
            .build();
    }
  }
}
