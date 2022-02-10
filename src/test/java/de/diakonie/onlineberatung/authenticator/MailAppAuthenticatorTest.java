package de.diakonie.onlineberatung.authenticator;

import static de.diakonie.onlineberatung.RealmOtpResourceProvider.OTP_MAIL_AUTHENTICATION_ATTRIBUTE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import de.diakonie.onlineberatung.otp.OtpAuthenticator;
import org.jboss.resteasy.spi.HttpRequest;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;

public class MailAppAuthenticatorTest {

  private AuthenticationFlowContext authFlow;
  private MailAppAuthenticator authenticator;
  private RealmModel realm;
  private UserModel user;
  private OtpAuthenticator appAuthenticator;
  private OtpAuthenticator mailAuthenticator;
  private UserCredentialManager credentialManager;

  @Before
  public void setUp() {
    authFlow = mock(AuthenticationFlowContext.class);
    when(authFlow.getHttpRequest()).thenReturn(mock(HttpRequest.class));
    realm = mock(RealmModel.class);
    when(authFlow.getRealm()).thenReturn(realm);
    user = mock(UserModel.class);
    when(authFlow.getUser()).thenReturn(user);
    var session = mock(KeycloakSession.class);
    when(authFlow.getSession()).thenReturn(session);
    credentialManager = mock(UserCredentialManager.class);
    when(session.userCredentialManager()).thenReturn(credentialManager);
    appAuthenticator = mock(OtpAuthenticator.class);
    mailAuthenticator = mock(OtpAuthenticator.class);
    authenticator = new MailAppAuthenticator(appAuthenticator, mailAuthenticator);
  }

  @Test
  public void authenticate_should_authenticate_via_app_if_configured() {
    when(credentialManager.isConfiguredFor(realm, user, OTPCredentialModel.TYPE)).thenReturn(true);

    authenticator.authenticate(authFlow);

    verify(appAuthenticator).authenticate(authFlow);
    verifyNoInteractions(mailAuthenticator);
  }

  @Test
  public void authenticate_should_authenticate_via_mail_if_configured() {
    when(credentialManager.isConfiguredFor(realm, user, OTPCredentialModel.TYPE)).thenReturn(false);
    when(user.getFirstAttribute(OTP_MAIL_AUTHENTICATION_ATTRIBUTE)).thenReturn("true");

    authenticator.authenticate(authFlow);

    verify(mailAuthenticator).authenticate(authFlow);
    verifyNoInteractions(appAuthenticator);
  }

  @Test
  public void authenticate_should_be_successful_if_no_2Fa_is_configured() {
    when(credentialManager.isConfiguredFor(realm, user, OTPCredentialModel.TYPE)).thenReturn(false);

    authenticator.authenticate(authFlow);

    verify(authFlow).success();
    verifyNoInteractions(appAuthenticator, mailAuthenticator);
  }
}