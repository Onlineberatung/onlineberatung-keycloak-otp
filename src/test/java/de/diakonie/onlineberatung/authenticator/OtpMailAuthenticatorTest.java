package de.diakonie.onlineberatung.authenticator;

import static de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType.EMAIL;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.diakonie.onlineberatung.credential.MailOtpCredentialModel;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import de.diakonie.onlineberatung.otp.Otp;
import de.diakonie.onlineberatung.otp.OtpMailSender;
import de.diakonie.onlineberatung.otp.OtpService;
import java.io.IOException;
import java.time.Clock;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.Response;
import org.jboss.resteasy.spi.HttpRequest;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.mockito.ArgumentCaptor;

public class OtpMailAuthenticatorTest {

  private AuthenticationFlowContext authFlow;
  private OtpMailSender mailSender;
  private OtpService otpService;
  private OtpMailAuthenticator authenticator;
  private KeycloakSession session;
  private RealmModel realm;

  @Before
  public void setUp() {
    authFlow = mock(AuthenticationFlowContext.class);
    var httpRequest = mock(HttpRequest.class);
    when(authFlow.getHttpRequest()).thenReturn(httpRequest);
    var decodedFormParams = new MultivaluedHashMap<String, String>();
    when(httpRequest.getDecodedFormParameters()).thenReturn(decodedFormParams);
    mailSender = mock(OtpMailSender.class);
    otpService = mock(OtpService.class);
    realm = mock(RealmModel.class);
    when(authFlow.getRealm()).thenReturn(realm);
    session = mock(KeycloakSession.class);
    when(authFlow.getSession()).thenReturn(session);

    authenticator = new OtpMailAuthenticator(otpService, mailSender);
  }

  @Test
  public void isConfigured_should_be_true_if_credential_is_active() {
    var user = mock(UserModel.class);
    var credentialModel = MailOtpCredentialModel.createOtpModel(
        new Otp("1234", 300, 1000L, "someemail@test.de", 0, true),
        Clock.systemDefaultZone());
    when(authFlow.getUser()).thenReturn(user);
    when(otpService.getCredential(session, realm, user)).thenReturn(credentialModel);

    var configured = authenticator.configuredFor(session, realm, user);

    assertThat(configured).isTrue();
  }

  @Test
  public void isConfigured_should_be_false_if_credential_is_inactive() {
    var user = mock(UserModel.class);
    when(authFlow.getUser()).thenReturn(user);
    var credentialModel = MailOtpCredentialModel.createOtpModel(
        new Otp("1234", 300, 1000L, "someemail@test.de", 0, false),
        Clock.systemDefaultZone());
    when(otpService.getCredential(session, realm, user)).thenReturn(credentialModel);

    var configured = authenticator.configuredFor(session, realm, user);

    assertThat(configured).isFalse();
  }

  @Test
  public void isConfigured_should_be_false_if_mail_attribute_is_not_set() {
    var user = mock(UserModel.class);
    when(authFlow.getUser()).thenReturn(user);

    var configured = authenticator.configuredFor(session, realm, user);

    assertThat(configured).isFalse();
  }

  @Test
  public void authenticate_should_send_mail_if_otp_param_is_missing() throws Exception {
    var user = mock(UserModel.class);
    when(user.getUsername()).thenReturn("Karen");
    when(user.getEmail()).thenReturn("mymail@test.de");
    when(authFlow.getUser()).thenReturn(user);
    var expectedOtp = new Otp("123", 200L, 123456L, "mymail@test.de", 0, true);
    var credentialModel = MailOtpCredentialModel.createOtpModel(expectedOtp,
        Clock.systemDefaultZone());
    when(otpService.getCredential(session, realm, user)).thenReturn(credentialModel);

    when(otpService.createOtp("mymail@test.de", true)).thenReturn(expectedOtp);

    authenticator.authenticate(authFlow);

    var responseCaptor = ArgumentCaptor.forClass(Response.class);
    verify(authFlow).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS),
        responseCaptor.capture());
    assertThat(responseCaptor.getValue().getStatus()).isEqualTo(400);
    var challenge = responseCaptor.getValue().readEntity(Challenge.class);
    assertThat(challenge.getOtpType()).isEqualTo(EMAIL);
    verify(mailSender).sendOtpCode(eq(expectedOtp), any(), eq(user), eq("mymail@test.de"));
  }

  @Test
  public void authenticate_should_invalidate_otp_if_mail_sending_fails() throws Exception {
    var user = mock(UserModel.class);
    when(user.getUsername()).thenReturn("Karen");
    when(user.getEmail()).thenReturn("mymail@test.de");
    when(authFlow.getUser()).thenReturn(user);
    var expectedOtp = new Otp("123", 200L, 123456L, "mymail@test.de", 0, true);
    when(otpService.createOtp("mymail@test.de", true)).thenReturn(expectedOtp);
    doThrow(IOException.class).when(mailSender).sendOtpCode(any(), any(), any(), any());
    var credentialModel = MailOtpCredentialModel.createOtpModel(
        new Otp("123", 11L, 112L, null, 0, true),
        Clock.systemDefaultZone());
    when(otpService.getCredential(session, realm, user)).thenReturn(
        credentialModel);

    authenticator.authenticate(authFlow);

    var responseCaptor = ArgumentCaptor.forClass(Response.class);
    verify(authFlow).failure(eq(AuthenticationFlowError.INTERNAL_ERROR),
        responseCaptor.capture());
    assertThat(responseCaptor.getValue().getStatus()).isEqualTo(500);
    verify(otpService).invalidate(credentialModel, realm, user);
  }
}