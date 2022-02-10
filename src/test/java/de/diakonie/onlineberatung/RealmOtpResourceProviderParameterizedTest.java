package de.diakonie.onlineberatung;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.diakonie.onlineberatung.authenticator.SessionAuthenticator;
import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpSetupDTO;
import de.diakonie.onlineberatung.mail.OtpMailSender;
import de.diakonie.onlineberatung.otp.OtpService;
import de.diakonie.onlineberatung.otp.ValidationResult;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

@RunWith(Parameterized.class)
public class RealmOtpResourceProviderParameterizedTest {

  @Parameters(name = "Test {index}: setupOtpMail({0})={1}")
  public static Collection<Object[]> data() {
    return Arrays.asList(new Object[][]{
        {ValidationResult.VALID, 201},
        {ValidationResult.INVALID, 401},
        {ValidationResult.TOO_MANY_FAILED_ATTEMPTS, 429},
        {ValidationResult.NOT_PRESENT, 401},
        {ValidationResult.EXPIRED, 401}
    });
  }

  private final ValidationResult input;
  private final int httpStatusExpected;

  public RealmOtpResourceProviderParameterizedTest(ValidationResult input, int httpStatusExpected) {
    this.input = input;
    this.httpStatusExpected = httpStatusExpected;
  }

  private OtpService otpService;
  private RealmOtpResourceProvider resourceProvider;

  @Before
  public void setUp() {
    var session = mock(KeycloakSession.class);
    otpService = mock(OtpService.class);
    var mailSender = mock(OtpMailSender.class);
    var sessionAuthenticator = mock(SessionAuthenticator.class);
    var keycloakContext = mock(KeycloakContext.class);
    when(session.getContext()).thenReturn(keycloakContext);
    var realmModel = mock(RealmModel.class);
    when(keycloakContext.getRealm()).thenReturn(realmModel);
    var userProvider = mock(UserProvider.class);
    when(session.users()).thenReturn(userProvider);
    var user = mock(UserModel.class);
    when(userProvider.getUserByUsername(realmModel, "heinrich")).thenReturn(user);
    resourceProvider = new RealmOtpResourceProvider(session, otpService, mailSender,
        sessionAuthenticator);
  }

  @Test
  public void setupOtpMail_response_on_validation_result() {
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("hk@test.de");
    when(otpService.validate(mailSetup.getInitialCode(), "hk@test.de")).thenReturn(input);

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(httpStatusExpected);
  }

}