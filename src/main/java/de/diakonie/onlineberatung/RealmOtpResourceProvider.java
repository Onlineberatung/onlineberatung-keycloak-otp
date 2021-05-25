package de.diakonie.onlineberatung;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.utils.CredentialHelper;
import org.keycloak.utils.TotpUtils;

public class RealmOtpResourceProvider implements RealmResourceProvider {

  private final KeycloakSession session;

  public RealmOtpResourceProvider(KeycloakSession session) {
    this.session = session;
  }

  @GET
  @Path("fetch-otp-setup-info")
  @Produces({MediaType.APPLICATION_JSON})
  public OtpInfoDTO getOtpSetupInfo(@PathParam("username") final String username) {
    final RealmModel realm = this.session.getContext().getRealm();
    final UserModel user = this.session.users().getUserByUsername(username, realm);

    OtpInfoDTO otpInfoDTO = new OtpInfoDTO();
    otpInfoDTO.setOtpSetup(
        this.session.userCredentialManager().isConfiguredFor(realm, user, OTPCredentialModel.TYPE));

    if (!otpInfoDTO.isOtpSetup()) {
      String otpSecret = HmacOTP.generateSecret(20);
      otpInfoDTO.setOtpSecret(otpSecret);
      otpInfoDTO.setOtpSecretQrCode(TotpUtils.qrCode(otpSecret, realm, user));
    }

    return otpInfoDTO;
  }

  @POST
  @Path("setup-otp")
  @Consumes("application/json")
  public void setupOtp(@PathParam("username") final String username, final OtpSetupDTO dto) {
    final RealmModel realm = this.session.getContext().getRealm();
    final UserModel user = this.session.users().getUserByUsername(username, realm);
    final OTPCredentialModel otpCredentialModel = OTPCredentialModel
        .createFromPolicy(realm, dto.getSecret());
    CredentialHelper
        .createOTPCredential(this.session, realm, user, dto.getInitialCode(), otpCredentialModel);
  }

  @Override
  public Object getResource() {
    return this;
  }

  @Override
  public void close() {

  }
}
