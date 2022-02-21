package de.diakonie.onlineberatung;

import static de.diakonie.onlineberatung.credential.MailOtpCredentialModel.INVALIDATED;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.diakonie.onlineberatung.authenticator.SessionAuthenticator;
import de.diakonie.onlineberatung.credential.CredentialContext;
import de.diakonie.onlineberatung.credential.CredentialService;
import de.diakonie.onlineberatung.credential.MailOtpCredentialModel;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpSetupDTO;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.SuccessWithEmail;
import de.diakonie.onlineberatung.mail.MailSendingException;
import de.diakonie.onlineberatung.otp.Otp;
import de.diakonie.onlineberatung.otp.OtpMailSender;
import de.diakonie.onlineberatung.otp.OtpService;
import de.diakonie.onlineberatung.otp.ValidationResult;
import java.time.Clock;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.credential.OTPCredentialModel;

public class RealmOtpResourceProviderTest {

  private KeycloakSession session;
  private OtpService otpService;
  private OtpMailSender mailSender;
  private RealmOtpResourceProvider resourceProvider;
  private UserModel user;
  private UserProvider userProvider;
  private RealmModel realm;
  private CredentialService credentialService;
  private CredentialContext credentialContext;
  private UserCredentialManager userCredentialManager;

  @Before
  public void setUp() {
    session = mock(KeycloakSession.class);
    otpService = mock(OtpService.class);
    credentialService = mock(CredentialService.class);
    mailSender = mock(OtpMailSender.class);
    var sessionAuthenticator = mock(SessionAuthenticator.class);
    var keycloakContext = mock(KeycloakContext.class);
    when(session.getContext()).thenReturn(keycloakContext);
    realm = mock(RealmModel.class);
    when(keycloakContext.getRealm()).thenReturn(realm);
    userProvider = mock(UserProvider.class);
    when(session.users()).thenReturn(userProvider);
    user = mock(UserModel.class);
    credentialContext = new CredentialContext(session, realm, user);
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    userCredentialManager = mock(UserCredentialManager.class);
    when(session.userCredentialManager()).thenReturn(userCredentialManager);
    when(userCredentialManager.isConfiguredFor(any(), any(), any())).thenReturn(false);
    resourceProvider = new RealmOtpResourceProvider(session, otpService, mailSender,
        sessionAuthenticator, credentialService);
  }

  @Test
  public void sendVerificationMail_should_create_and_send_otp() {
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("hk@test.de");
    var otp = new Otp("123", 450L, 1234567L, "hk@test.de", 0);
    when(otpService.createOtp("hk@test.de")).thenReturn(otp);

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(200);
    verify(mailSender).sendOtpCode(otp, session, user);
  }

  @Test
  public void sendVerificationMail_should_update_and_send_credentials_if_mail_was_already_send_but_not_verified_yet() {
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("hk@test.de");
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    var oldOtp = new Otp("1223", 1L, 2L, "hk@test.de", 0);
    var notYetActivatedCredentials = MailOtpCredentialModel.createOtpModel(oldOtp,
        Clock.systemDefaultZone(), false);
    when(credentialService.getCredential(credentialContext)).thenReturn(notYetActivatedCredentials);
    var newOtp = new Otp("667722", 1L, 3L, "hk@test.de", 0);
    when(otpService.createOtp("hk@test.de")).thenReturn(newOtp);

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(200);
    var expectedCredentials = notYetActivatedCredentials.updateFrom(newOtp);
    verify(mailSender).sendOtpCode(newOtp, session, user);
    verify(credentialService).update(expectedCredentials, credentialContext);
  }

  @Test
  public void sendVerificationMail_should_be_bad_request_if_user_not_found() {
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(null);
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("hk@test.de");

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(400);
  }

  @Test
  public void sendVerificationMail_should_be_bad_request_if_no_email_given() {
    var mailSetup = new OtpSetupDTO();
    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(400);
  }

  @Test
  public void sendVerificationMail_should_invalidate_otp_if_sending_fails() {
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("hk@test.de");
    var otp = new Otp("123", 450L, 1234567L, "hk@test.de", 0);
    when(otpService.createOtp("hk@test.de")).thenReturn(otp);
    doThrow(MailSendingException.class).when(mailSender).sendOtpCode(any(), any(), any());
    var credentialModel = MailOtpCredentialModel.createOtpModel(otp, Clock.systemDefaultZone());
    when(credentialService.createCredential(otp, credentialContext)).thenReturn(credentialModel);

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(500);
    verify(credentialService).invalidate(credentialModel, credentialContext);
  }

  @Test
  public void sendVerification_should_return_conflict_if_credentials_are_already_activated() {
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("test@test.de");
    var otp = new Otp("1223", 1L, 2L, "hk@test.de", 0);
    var activatedCredentials = MailOtpCredentialModel.createOtpModel(otp, Clock.systemDefaultZone(),
        true);
    when(credentialService.getCredential(credentialContext)).thenReturn(activatedCredentials);
    when(credentialService.createCredential(otp, credentialContext)).thenReturn(
        activatedCredentials);

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(409);
  }

  @Test
  public void sendVerification_should_be_conflict_if_2fa_via_app_is_already_configured() {
    var mailSetup = new OtpSetupDTO();
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    when(userCredentialManager.isConfiguredFor(realm, user, OTPCredentialModel.TYPE)).thenReturn(
        true);

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(409);
  }

  @Test
  public void setupOtpMail_should_be_bad_request_if_user_not_found() {
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(null);
    var mailSetup = new OtpSetupDTO();

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(400);
  }

  @Test
  public void setupOtpMail_should_send_email_address_as_response_upon_successful_otp_creation() {
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    var mailSetup = new OtpSetupDTO();
    mailSetup.setInitialCode("1223");
    var otp = new Otp("1223", 1L, 2L, "hk@test.de", 0);
    var credentialModel = MailOtpCredentialModel.createOtpModel(otp, Clock.systemDefaultZone());
    when(otpService.validate("1223", otp)).thenReturn(
        ValidationResult.VALID);
    when(credentialService.getCredential(credentialContext)).thenReturn(credentialModel);
    when(credentialService.createCredential(otp, credentialContext)).thenReturn(credentialModel);

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(201);
    var otpWithEmailSuccess = response.readEntity(SuccessWithEmail.class);
    assertThat(otpWithEmailSuccess.getEmail()).isEqualTo("hk@test.de");
    assertThat(credentialModel.getOtp().getCode()).isEqualTo(INVALIDATED);
    verify(credentialService).update(credentialModel, credentialContext);
  }

  @Test
  public void setupOtpMail_should_return_bad_request_if_no_credentials_exist() {
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    var mailSetup = new OtpSetupDTO();
    mailSetup.setInitialCode("1223");

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(400);
  }

  @Test
  public void setupOtpMail_should_return_ok_if_already_configured_for_user() {
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    var mailSetup = new OtpSetupDTO();
    mailSetup.setInitialCode("1223");
    var otp = new Otp("1223", 1L, 2L, "hk@test.de", 0);
    var activatedCredentials = MailOtpCredentialModel.createOtpModel(otp, Clock.systemDefaultZone(),
        true);
    when(credentialService.getCredential(credentialContext)).thenReturn(activatedCredentials);
    when(credentialService.createCredential(otp, credentialContext)).thenReturn(
        activatedCredentials);

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(200);
  }

  @Test
  public void setupOtpMail_should_be_conflict_if_2fa_via_app_is_already_configured() {
    var mailSetup = new OtpSetupDTO();
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    when(userCredentialManager.isConfiguredFor(realm, user, OTPCredentialModel.TYPE)).thenReturn(
        true);

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(409);
  }
}