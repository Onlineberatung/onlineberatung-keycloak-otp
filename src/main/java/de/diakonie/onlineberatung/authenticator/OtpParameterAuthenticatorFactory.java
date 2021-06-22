package de.diakonie.onlineberatung.authenticator;

import java.util.Collections;
import java.util.List;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class OtpParameterAuthenticatorFactory implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "otp-parameter-authenticator";
  private static final OtpParameterAuthenticator SINGLETON = new OtpParameterAuthenticator();

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
      AuthenticationExecutionModel.Requirement.REQUIRED
   };

  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public Authenticator create(KeycloakSession keycloakSession) {
    return SINGLETON;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public String getDisplayType() {
    return "otp-parameter-validate";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public String getHelpText() {
    return "Validates if the otp or topt token is set";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return Collections.emptyList();
  }

  @Override
  public void init(Scope scope) {
    // Do nothing because it is not needed
  }

  @Override
  public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    // Do nothing because it is not needed
  }

  @Override
  public void close() {
    // Do nothing because it is not needed
  }
}
