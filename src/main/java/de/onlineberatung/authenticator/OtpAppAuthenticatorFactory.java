package de.onlineberatung.authenticator;

import static java.util.Arrays.asList;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class OtpAppAuthenticatorFactory implements AuthenticatorFactory {

  @Override
  public String getId() {
    return "app-authenticator";
  }

  @Override
  public String getDisplayType() {
    return "App Authentication";
  }

  @Override
  public String getHelpText() {
    return "Validates an OTP via App.";
  }

  @Override
  public String getReferenceCategory() {
    return "otp";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return new Requirement[]{Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.CONDITIONAL,
        Requirement.DISABLED,};
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return asList(
        new ProviderConfigProperty("length", "Code length",
            "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, 6),
        new ProviderConfigProperty("ttl", "Time-to-live",
            "The time to live in seconds for the code to be valid.",
            ProviderConfigProperty.STRING_TYPE, "300"),
        new ProviderConfigProperty("senderId", "SenderId",
            "The sender ID is displayed as the message sender on the receiving device.",
            ProviderConfigProperty.STRING_TYPE, "Keycloak"),
        new ProviderConfigProperty("simulation", "Simulation mode",
            "In simulation mode, the EMAIL won't be sent, but printed to the server logs",
            ProviderConfigProperty.BOOLEAN_TYPE, true)
    );
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new OtpParameterAuthenticator();
  }

  @Override
  public void init(Config.Scope config) {
    // unused
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // unused
  }

  @Override
  public void close() {
    // unused
  }


}
