package de.diakonie.onlineberatung;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import de.diakonie.onlineberatung.authenticator.SessionAuthenticator;
import de.diakonie.onlineberatung.credential.AppOtpCredentialService;
import de.diakonie.onlineberatung.credential.CredentialContext;
import de.diakonie.onlineberatung.credential.MailOtpCredentialService;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Error;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpInfoDTO;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpSetupDTO;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Success;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.SuccessWithEmail;
import de.diakonie.onlineberatung.mail.MailSendingException;
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
import org.keycloak.services.resource.RealmResourceProvider;

public class RealmOtpResourceProvider implements RealmResourceProvider {

  private static final Logger logger = Logger.getLogger(RealmOtpResourceProvider.class);
  private static final String MISSING_PARAMETER_ERROR = "invalid_parameter";
  private static final String INVALID_GRANT_ERROR = "invalid_grant";
  private static final String MAIL_OTP_ALREADY_ACTIVE = "mail otp credentials are already configured";
  private static final String APP_OTP_ALREADY_ACTIVE = "app otp credentials are already configured";
  private static final String MISSING_CREDENTIAL_CONFIG = "no mail otp credentials configured";
  private static final String MISSING_USERNAME_ERROR_DESCRIPTION = "username not found";
  private static final String MISSING_EMAIL_ADDRESS_ERROR_DESCRIPTION = "email address of user not available";
  private final static String FAILED_TO_SENT = "failed to send otp verification email";

  private final KeycloakSession session;
  private final SessionAuthenticator sessionAuthenticator;
  private final OtpService otpService;
  private final OtpMailSender mailSender;
  private final AppOtpCredentialService appCredentialService;
  private final MailOtpCredentialService mailCredentialService;

  public RealmOtpResourceProvider(KeycloakSession session, OtpService otpService,
      OtpMailSender mailSender, SessionAuthenticator sessionAuthenticator,
      AppOtpCredentialService appCredentialService,
      MailOtpCredentialService mailCredentialService) {
    this.session = session;
    this.otpService = otpService;
    this.mailSender = mailSender;
    this.sessionAuthenticator = sessionAuthenticator;
    this.appCredentialService = appCredentialService;
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

    var credentialContext = new CredentialContext(session, realm, user);
    if (appCredentialService.is2FAConfigured(credentialContext)) {
      otpInfoDTO.setOtpSetup(true);
      otpInfoDTO.setOtpType(OtpType.APP);
      return Response.ok(otpInfoDTO).build();
    }

    if (mailCredentialService.is2FAConfigured(credentialContext)) {
      otpInfoDTO.setOtpSetup(true);
      otpInfoDTO.setOtpType(OtpType.EMAIL);
      return Response.ok(otpInfoDTO).build();
    }

    otpInfoDTO.setOtpSetup(false);
    var otpSecret = appCredentialService.generateSecret();
    otpInfoDTO.setOtpSecret(otpSecret);
    var qrCode = appCredentialService.generateQRCodeBase64(otpSecret, credentialContext);
    otpInfoDTO.setOtpSecretQrCode(qrCode);
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
    var credentialContext = new CredentialContext(session, realm, user);
    if (mailCredentialService.is2FAConfigured(credentialContext)) {
      return Response.status(Status.CONFLICT).entity(new Error().error(MAIL_OTP_ALREADY_ACTIVE))
          .build();
    }
    if (appCredentialService.is2FAConfigured(credentialContext)) {
      return Response.ok(new Success().info("OTP credential is already configured for this user"))
          .build();
    }

    final var credentialModel = appCredentialService.createModel(dto.getSecret(),
        credentialContext);

    if (!appCredentialService.validate(dto.getInitialCode(), credentialModel, credentialContext)) {
      return Response.status(Status.UNAUTHORIZED)
          .entity(new Error().error(INVALID_GRANT_ERROR).errorDescription("Invalid otp code"))
          .build();
    }

    appCredentialService.createCredential(dto.getInitialCode(), credentialModel, credentialContext);

    return Response.status(Status.CREATED)
        .entity(new Success().info("OTP credential created")).build();
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
    var credentialContext = new CredentialContext(session, realm, user);

    appCredentialService.deleteCredentials(credentialContext);
    mailCredentialService.deleteCredential(credentialContext);

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

    var context = new CredentialContext(session, realm, user);
    if (appCredentialService.is2FAConfigured(context)) {
      return Response.status(Status.CONFLICT).entity(new Error().error(APP_OTP_ALREADY_ACTIVE))
          .build();
    }

    var emailAddress = mailSetup.getEmail();
    if (isNull(emailAddress) || emailAddress.isBlank()) {
      return Response.status(Status.BAD_REQUEST).entity(new Error().error(MISSING_PARAMETER_ERROR)
          .errorDescription(MISSING_EMAIL_ADDRESS_ERROR_DESCRIPTION)).build();
    }

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
    if (appCredentialService.is2FAConfigured(context)) {
      return Response.status(Status.CONFLICT).entity(new Error().error(APP_OTP_ALREADY_ACTIVE))
          .build();
    }

    try {
      return verifyMailSetup(mailSetup.getInitialCode(), context);
    } catch (Exception e) {
      logger.error("failed to verify mail setup", e);
      return Response.status(Status.INTERNAL_SERVER_ERROR)
          .entity(
              new Error().error("internal_error").errorDescription("failed to verify mail setup"))
          .build();
    }
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
    var credentialModel = mailCredentialService.getCredential(context);
    if (isNull(credentialModel)) {
      credentialModel = mailCredentialService.createCredential(otp, context);
    } else if (credentialModel.isActive()) {
      return Response.status(Status.CONFLICT).entity(new Error().error(MAIL_OTP_ALREADY_ACTIVE))
          .build();
    } else {
      mailCredentialService.update(credentialModel.updateFrom(otp), context);
    }

    try {
      mailSender.sendOtpCode(otp, context);
    } catch (MailSendingException e) {
      if (nonNull(credentialModel)) {
        mailCredentialService.invalidate(credentialModel, context);
      }
      logger.error("failed to send verification mail", e);
      return Response.status(Status.INTERNAL_SERVER_ERROR)
          .entity(new Error().error(FAILED_TO_SENT))
          .build();
    }

    return Response.status(Status.OK).entity(new Success().info("OTP mail sent")).build();
  }

  private Response verifyMailSetup(String initialCode, CredentialContext context) {
    var credentialModel = mailCredentialService.getCredential(context);
    if (isNull(credentialModel)) {
      return Response.status(Status.BAD_REQUEST).entity(
              new Error().error(INVALID_GRANT_ERROR).errorDescription(MISSING_CREDENTIAL_CONFIG))
          .build();
    }

    var otp = credentialModel.getOtp();
    if (credentialModel.isActive()) {
      return Response.ok(
          new SuccessWithEmail().info("Mail OTP credential is already configured for this User")
              .email(otp.getEmail())).build();
    }

    var validationResult = otpService.validate(initialCode, otp);
    switch (validationResult) {
      case NOT_PRESENT:
        return Response.status(Status.UNAUTHORIZED).entity(
                new Error().error(INVALID_GRANT_ERROR).errorDescription("No corresponding code"))
            .build();
      case EXPIRED:
        return Response.status(Status.UNAUTHORIZED).entity(
            new Error().error(INVALID_GRANT_ERROR).errorDescription("Code expired")).build();
      case INVALID:
        mailCredentialService.incrementFailedAttempts(credentialModel, context,
            otp.getFailedVerifications());
        return Response.status(Status.UNAUTHORIZED).entity(
            new Error().error(INVALID_GRANT_ERROR).errorDescription("Invalid code")).build();
      case TOO_MANY_FAILED_ATTEMPTS:
        return Response.status(Status.TOO_MANY_REQUESTS).entity(
            new Error().error(INVALID_GRANT_ERROR)
                .errorDescription("Maximal number of failed attempts reached")).build();
      case VALID:
        mailCredentialService.activate(credentialModel, context);
        return Response.status(Status.CREATED)
            .entity(new SuccessWithEmail().email(otp.getEmail()).info("OTP setup created"))
            .build();
      default:
        return Response.status(Status.INTERNAL_SERVER_ERROR).entity(
                new Error().error(INVALID_GRANT_ERROR).errorDescription("failed to validate code"))
            .build();
    }
  }
}
