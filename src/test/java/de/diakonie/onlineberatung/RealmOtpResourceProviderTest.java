package de.diakonie.onlineberatung;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.diakonie.onlineberatung.authenticator.SessionAuthenticator;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpSetupDTO;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.SuccessWithEmail;
import de.diakonie.onlineberatung.otp.OtpMailSender;
import de.diakonie.onlineberatung.otp.Otp;
import de.diakonie.onlineberatung.otp.OtpService;
import de.diakonie.onlineberatung.otp.ValidationResult;
import java.io.IOException;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

public class RealmOtpResourceProviderTest {

  private KeycloakSession session;
  private OtpService otpService;
  private OtpMailSender mailSender;
  private RealmOtpResourceProvider resourceProvider;
  private UserModel user;
  private UserProvider userProvider;
  private RealmModel realmModel;

  @Before
  public void setUp() {
    session = mock(KeycloakSession.class);
    otpService = mock(OtpService.class);
    mailSender = mock(OtpMailSender.class);
    var sessionAuthenticator = mock(SessionAuthenticator.class);
    var keycloakContext = mock(KeycloakContext.class);
    when(session.getContext()).thenReturn(keycloakContext);
    realmModel = mock(RealmModel.class);
    when(keycloakContext.getRealm()).thenReturn(realmModel);
    userProvider = mock(UserProvider.class);
    when(session.users()).thenReturn(userProvider);
    user = mock(UserModel.class);
    when(userProvider.getUserByUsername(realmModel, "heinrich")).thenReturn(user);
    resourceProvider = new RealmOtpResourceProvider(session, otpService, mailSender,
        sessionAuthenticator);
  }

  @Test
  public void sendVerificationMail_should_create_and_send_otp() throws Exception {
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("hk@test.de");
    var otp = new Otp("123", 450L, 1234567L, "hk@test.de");
    when(otpService.createOtp("heinrich", "hk@test.de")).thenReturn(otp);

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(200);
    verify(mailSender).sendOtpCode(otp, session, user, "hk@test.de");
  }

  @Test
  public void sendVerificationMail_should_be_bad_request_if_user_not_found() {
    when(userProvider.getUserByUsername(realmModel, "heinrich")).thenReturn(null);
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
  public void sendVerificationMail_should_invalidate_otp_if_sending_fails() throws Exception {
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("hk@test.de");
    var otp = new Otp("123", 450L, 1234567L, "hk@test.de");
    when(otpService.createOtp("heinrich", "hk@test.de")).thenReturn(otp);
    doThrow(IOException.class).when(mailSender).sendOtpCode(any(), any(), any(), any());

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(500);
    verify(otpService).invalidate("heinrich");
  }

  @Test
  public void setupOtpMail_should_be_bad_request_if_user_not_found() {
    when(userProvider.getUserByUsername(realmModel, "heinrich")).thenReturn(null);
    var mailSetup = new OtpSetupDTO();

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(400);
  }

  @Test
  public void setupOtpMail_should_send_email_as_response_upon_successful_otp_creation() {
    when(userProvider.getUserByUsername(realmModel, "heinrich")).thenReturn(user);
    var mailSetup = new OtpSetupDTO();
    mailSetup.setInitialCode("1223");
    when(otpService.get("heinrich")).thenReturn(new Otp("1223", 1L, 2L, "hk@test.de"));
    when(otpService.validate("1223", "heinrich")).thenReturn(ValidationResult.VALID);

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(201);
    var otpWithEmailSuccess = response.readEntity(SuccessWithEmail.class);
    assertThat(otpWithEmailSuccess.getEmail()).isEqualTo("hk@test.de");
    var inOrder = inOrder(otpService, otpService);
    inOrder.verify(otpService).get("heinrich");
    inOrder.verify(otpService).validate("1223", "heinrich");
  }

}