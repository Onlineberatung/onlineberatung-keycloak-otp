package de.diakonie.onlineberatung.authenticator;

import static java.util.Objects.isNull;

import de.diakonie.onlineberatung.otp.OtpAuthenticator;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

public class MultiOtpAuthenticator extends AbstractDirectGrantAuthenticator {

  public static final String ID = "multi-otp-authenticator";

  final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
      AuthenticationExecutionModel.Requirement.REQUIRED};

  private final Collection<OtpAuthenticator> authenticators;

  public MultiOtpAuthenticator(Collection<OtpAuthenticator> authenticators) {
    this.authenticators = authenticators;
  }

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    authenticators.stream()
        .filter(authenticator -> authenticator.isConfigured(context))
        .findFirst()
        .ifPresentOrElse(a -> a.authenticate(context), context::success);
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel,
      UserModel userModel) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel,
      UserModel userModel) {
    // Nothing to do here because configuredFor always returns true
  }

  @Override
  public String getDisplayType() {
    return "OTP Mail and App Validator";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return "Authenticates via configured OTP authenticators.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return Collections.emptyList();
  }

  static String extractDecodedOtpParam(AuthenticationFlowContext context) {
    var inputData = context.getHttpRequest().getDecodedFormParameters();
    var otpParam = inputData.getFirst("otp");
    otpParam = (isNull(otpParam)) ? inputData.getFirst("totp") : otpParam;
    return otpParam;
  }

}
