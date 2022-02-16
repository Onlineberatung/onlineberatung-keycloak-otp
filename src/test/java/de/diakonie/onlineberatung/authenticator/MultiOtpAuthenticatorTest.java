package de.diakonie.onlineberatung.authenticator;

import static java.util.Arrays.asList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import de.diakonie.onlineberatung.otp.OtpAuthenticator;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;

public class MultiOtpAuthenticatorTest {

  private AuthenticationFlowContext authFlow;
  private OtpAuthenticator appAuthenticator;
  private OtpAuthenticator mailAuthenticator;
  private MultiOtpAuthenticator authenticator;

  @Before
  public void setUp() {
    authFlow = mock(AuthenticationFlowContext.class);
    appAuthenticator = mock(OtpAuthenticator.class);
    mailAuthenticator = mock(OtpAuthenticator.class);
    authenticator = new MultiOtpAuthenticator(asList(appAuthenticator, mailAuthenticator));
  }

  @Test
  public void authenticate_should_authenticate_with_first_configured_authenticator() {
    when(appAuthenticator.isConfigured(any())).thenReturn(true);
    when(mailAuthenticator.isConfigured(any())).thenReturn(true);

    authenticator.authenticate(authFlow);

    verify(appAuthenticator).authenticate(authFlow);
    verifyNoInteractions(mailAuthenticator);
  }

  @Test
  public void authenticate_should_authenticate_with_configured_authenticator() {
    when(appAuthenticator.isConfigured(any())).thenReturn(false);
    when(mailAuthenticator.isConfigured(any())).thenReturn(true);

    authenticator.authenticate(authFlow);

    verify(mailAuthenticator).authenticate(authFlow);
    verify(appAuthenticator, never()).authenticate(any());
  }

  @Test
  public void authenticate_should_be_successful_if_no_authenticator_is_configured() {
    authenticator.authenticate(authFlow);

    verify(authFlow).success();
    verify(appAuthenticator, never()).authenticate(any());
    verify(mailAuthenticator, never()).authenticate(any());
  }
}