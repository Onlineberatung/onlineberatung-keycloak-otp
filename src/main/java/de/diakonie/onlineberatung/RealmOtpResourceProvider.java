package de.diakonie.onlineberatung;

import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Error;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpInfoDTO;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpSetupDTO;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Success;
import java.util.Objects;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.GET;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.CredentialValidation;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.utils.CredentialHelper;
import org.keycloak.utils.TotpUtils;

public class RealmOtpResourceProvider implements RealmResourceProvider {

  public static final int KEY_LENGTH = 32;
  public static final String ROLE_REQUIRED = "technical";

  private static final String MISSING_USERNAME_ERROR = "invalid_parameter";
  private static final String MISSING_USERNAME_ERROR_DESCRIPTION = "username not found";

  private final KeycloakSession session;

  public RealmOtpResourceProvider(KeycloakSession session) {
    this.session = session;
  }

  @GET
  @Path("fetch-otp-setup-info/{username}")
  @Produces({MediaType.APPLICATION_JSON})
  public Response getOtpSetupInfo(@PathParam("username") final String username) {
    verifyAuthentication();

    final RealmModel realm = this.session.getContext().getRealm();
    final UserModel user = this.session.users().getUserByUsername(username, realm);

    if (Objects.isNull(user)) {
      return Response.status(Status.BAD_REQUEST).entity(new Error().error(MISSING_USERNAME_ERROR)
          .errorDescription(MISSING_USERNAME_ERROR_DESCRIPTION)).build();
    }

    var otpInfoDTO = new OtpInfoDTO();
    otpInfoDTO.setOtpSetup(
        this.session.userCredentialManager().isConfiguredFor(realm, user, OTPCredentialModel.TYPE));

    if (Boolean.FALSE.equals(otpInfoDTO.getOtpSetup())) {
      String otpSecret = HmacOTP.generateSecret(KEY_LENGTH);
      otpInfoDTO.setOtpSecret(otpSecret);
      otpInfoDTO.setOtpSecretQrCode(TotpUtils.qrCode(otpSecret, realm, user));
    }

    return Response.ok(otpInfoDTO).build();
  }

  @PUT
  @Path("setup-otp/{username}")
  @Consumes({MediaType.APPLICATION_JSON})
  public Response setupOtp(@PathParam("username") final String username, final OtpSetupDTO dto) {
    verifyAuthentication();

    final RealmModel realm = this.session.getContext().getRealm();
    final UserModel user = this.session.users().getUserByUsername(username, realm);

    if (Objects.isNull(user)) {
        return Response.status(Status.BAD_REQUEST).entity(new Error().error(MISSING_USERNAME_ERROR)
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

      return Response.status(Status.CREATED).entity(new Success().info("OTP credential created"))
          .build();
    }

    return Response.ok(new Success().info("OTP credential is already configured for this User"))
        .build();
  }

  @DELETE
  @Path("delete-otp/{username}")
  public Response deleteOtp(@PathParam("username") final String username) {
    verifyAuthentication();

    final RealmModel realm = this.session.getContext().getRealm();
    final UserModel user = this.session.users().getUserByUsername(username, realm);

    if (Objects.isNull(user)) {
        return Response.status(Status.BAD_REQUEST).entity(new Error().error(MISSING_USERNAME_ERROR)
            .errorDescription(MISSING_USERNAME_ERROR_DESCRIPTION)).build();
    }

    deleteAllOtpCredentials(realm, user);

    return Response.ok(new Success().info("OTP credential deleted")).build();
  }

  private void deleteAllOtpCredentials(RealmModel realm, UserModel user) {
    this.session.userCredentialManager().
        getStoredCredentialsByType(realm, user, OTPCredentialModel.TYPE).
        forEach(credentialModel -> CredentialHelper
            .deleteOTPCredential(this.session, realm, user, credentialModel.getId()));
  }

  private void verifyAuthentication() {
    final AuthenticationManager.AuthResult auth = new AppAuthManager()
        .authenticateBearerToken(session);

    if (auth == null) {
      throw new NotAuthorizedException("Bearer");
    } else if (Objects.isNull(auth.getUser()) || Objects.isNull(auth.getUser().getRoleMappings())
        || auth.getUser().getRoleMappings().stream().map(RoleModel::getName)
        .noneMatch(name -> Objects.equals(name, ROLE_REQUIRED))) {

      throw new ForbiddenException("Does not have required role");
    }
  }

  @Override
  public Object getResource() {
    return this;
  }

  @Override
  public void close() {
    // Do nothing because it is not needed
  }
}
