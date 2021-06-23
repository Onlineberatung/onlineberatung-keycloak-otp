package de.diakonie.onlineberatung;

import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpInfoDTO;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpSetupDTO;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.keycloak.authentication.authenticators.challenge.BasicAuthOTPAuthenticatorFactory;
import org.keycloak.authentication.authenticators.directgrant.ValidateOTP;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.utils.CredentialHelper;
import org.keycloak.utils.TotpUtils;

public class RealmOtpResourceProvider implements RealmResourceProvider {

  private final KeycloakSession session;

  /*private final AuthenticationManager.AuthResult authResult;

  private final AppAuthManager authManager;*/

  private TokenManager tokenManager;

  public RealmOtpResourceProvider(KeycloakSession session) {
    //this.authManager = new AppAuthManager();
    this.session = session;
    System.out.println("Realm: "+session.getContext().getRealm());
    System.out.println("Realm this: "+this.session.getContext().getRealm());
    /*System.out.println(session);

    System.out.println(session.getContext().getRequestHeaders());
    String tokenString = authManager.extractAuthorizationHeaderToken(session.getContext().getRequestHeaders());
    System.out.println("tokenString: "+tokenString);
    System.out.println("URI: "+session.getContext().getUri());
    System.out.println("Connection: "+ session.getContext().getConnection());
    this.authResult = authManager
        .authenticateBearerToken(tokenString, session, session.getContext().getRealm(), session.getContext().getUri(),
            session.getContext().getConnection(), session.getContext().getRequestHeaders());
    System.out.println(authResult);*/
  }

  @GET
  @Path("fetch-otp-setup-info/{username}")
  @Produces({MediaType.APPLICATION_JSON})
  public Response getOtpSetupInfo(@PathParam("username") final String username) {

    final RealmModel realm = this.session.getContext().getRealm();
    System.out.println(realm);
    final UserModel user = this.session.users().getUserByUsername(username, realm);

    var otpInfoDTO = new OtpInfoDTO();
    otpInfoDTO.setOtpSetup(
        this.session.userCredentialManager().isConfiguredFor(realm, user, OTPCredentialModel.TYPE));

    if (Boolean.FALSE.equals(otpInfoDTO.getOtpSetup())) {
      String otpSecret = HmacOTP.generateSecret(20);
      otpInfoDTO.setOtpSecret(otpSecret);
      otpInfoDTO.setOtpSecretQrCode(TotpUtils.qrCode(otpSecret, realm, user));
    }

    return Response.ok(otpInfoDTO).build();
  }

  @PUT
  @Path("setup-otp/{username}")
  @Consumes("application/json")
  public Response setupOtp(@PathParam("username") final String username, final OtpSetupDTO dto) {
    final RealmModel realm = this.session.getContext().getRealm();
    final UserModel user = this.session.users().getUserByUsername(username, realm);
    if (!this.session.userCredentialManager()
        .isConfiguredFor(realm, user, OTPCredentialModel.TYPE)) {
      final var otpCredentialModel = OTPCredentialModel
          .createFromPolicy(realm, dto.getSecret());
      boolean validCode = CredentialHelper
          .createOTPCredential(this.session, realm, user, dto.getInitialCode(), otpCredentialModel);

      if (Boolean.FALSE.equals(validCode)){
        deleteAllOtpCredentials(realm, user);
        return Response.status(Status.UNAUTHORIZED).build();
      }

      return Response.status(Status.CREATED).entity("OTP credential created").build();
    }

    return Response.ok("OTP credential is already configured for this User").build();
  }

  @DELETE
  @Path("delete-otp/{username}")
  public Response deleteOtp(@PathParam("username") final String username) {
    final RealmModel realm = this.session.getContext().getRealm();
    final UserModel user = this.session.users().getUserByUsername(username, realm);
    deleteAllOtpCredentials(realm, user);

    return Response.ok().build();
  }

  private void deleteAllOtpCredentials(RealmModel realm, UserModel user) {
    this.session.userCredentialManager().
        getStoredCredentialsByType(realm, user, OTPCredentialModel.TYPE).
        stream().map(CredentialModel::getId).
        forEach(id -> CredentialHelper.deleteOTPCredential(this.session, realm, user, id));
  }

  private boolean isAuthenticatedRequest() {
    /*System.out.println(httpHeaders);
    String tokenString = authManager.extractAuthorizationHeaderToken(httpHeaders);
    MultivaluedMap<String, String> queryParameters = session.getContext().getUri()
        .getQueryParameters();
    if (tokenString == null && queryParameters.containsKey("access_token")) {
      tokenString = queryParameters.getFirst("access_token");
    }
    if (tokenString == null) {
      return false;
    }
    AccessToken token;
    try {
      JWSInput input = new JWSInput(tokenString);
      token = input.readJsonContent(AccessToken.class);
    } catch (JWSInputException e) {
      return false;
    }
    String realmName = token.getIssuer().substring(token.getIssuer().lastIndexOf('/') + 1);
    RealmManager realmManager = new RealmManager(session);
    RealmModel realm = realmManager.getRealmByName(realmName);
    if (realm == null) {
      return false;
    }
    session.getContext().setRealm(realm);
    AuthenticationManager.AuthResult authResult = authManager
        .authenticateBearerToken(tokenString, session, realm, session.getContext().getUri(),
            clientConnection, httpHeaders);
    if (authResult == null) {
      return false;
    }

    ClientModel client = realm.getClientByClientId(token.getIssuedFor());
    if (client == null) {
      return false;
    }

    AdminAuth adminAuth = new AdminAuth(realm, authResult.getToken(), authResult.getUser(), client);
    adminAuth.getUser().getRealmRoleMappings().forEach(System.out::println);
    return false;*/
    return true;
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
