package de.diakonie.onlineberatung.authenticator;

import static de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType.APP;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.diakonie.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import java.util.Collections;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.Response;
import org.jboss.resteasy.spi.HttpRequest;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.mockito.ArgumentCaptor;

public class OtpParameterAuthenticatorTest {

  private OtpParameterAuthenticator authenticator;
  private AuthenticationFlowContext authFlow;
  private HttpRequest httpRequest;
  private MultivaluedHashMap<String, String> decodedFormParams;

  @Before
  public void setUp() {
    authFlow = mock(AuthenticationFlowContext.class);
    httpRequest = mock(HttpRequest.class);
    decodedFormParams = new MultivaluedHashMap<>();
    when(httpRequest.getDecodedFormParameters()).thenReturn(decodedFormParams);
    authenticator = new OtpParameterAuthenticator();
  }

  @Test
  public void should_fail_if_request_contains_no_form_params() {
    when(authFlow.getHttpRequest()).thenReturn(httpRequest);

    authenticator.authenticate(authFlow);

    var responseCaptor = ArgumentCaptor.forClass(Response.class);
    verify(authFlow).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS),
        responseCaptor.capture());
    assertThat(responseCaptor.getValue().getStatus()).isEqualTo(400);
    var challenge = responseCaptor.getValue().readEntity(Challenge.class);
    assertThat(challenge.getOtpType()).isEqualTo(APP);
  }

  @Test
  public void should_be_successful_if_form_params_contain_otp() {
    decodedFormParams.put("otp", Collections.singletonList("765432"));
    when(authFlow.getHttpRequest()).thenReturn(httpRequest);

    authenticator.authenticate(authFlow);
    verify(authFlow).success();
  }
}