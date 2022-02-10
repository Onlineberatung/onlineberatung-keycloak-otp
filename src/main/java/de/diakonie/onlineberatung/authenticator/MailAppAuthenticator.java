package de.diakonie.onlineberatung.authenticator;

import static de.diakonie.onlineberatung.RealmOtpResourceProvider.OTP_MAIL_AUTHENTICATION_ATTRIBUTE;
import static java.lang.Boolean.parseBoolean;
import static java.util.Objects.isNull;

import de.diakonie.onlineberatung.otp.OtpAuthenticator;
import java.util.Collections;
import java.util.List;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

public class MailAppAuthenticator extends AbstractDirectGrantAuthenticator {

  public static final String ID = "otp-mail-app-authenticator";

  final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
      AuthenticationExecutionModel.Requirement.REQUIRED};

  private final OtpAuthenticator appAuthenticator;
  private final OtpAuthenticator mailAuthenticator;

  public MailAppAuthenticator(OtpAuthenticator appAuthenticator,
      OtpAuthenticator mailAuthenticator) {
    this.appAuthenticator = appAuthenticator;
    this.mailAuthenticator = mailAuthenticator;
  }

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    RealmModel realm = context.getRealm();
    UserModel user = context.getUser();

    if (isApp2FaConfigured(context, realm, user)) {
      appAuthenticator.authenticate(context);
      return;
    }

    if (isMail2FaConfigured(user)) {
      mailAuthenticator.authenticate(context);
      return;
    }

    // no 2FA activated, but user is authenticated
    context.success();
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
    return "Validates if the otp parameter is set when OTP is enabled for the user, or if code sent via email is valid";
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

  private boolean isApp2FaConfigured(AuthenticationFlowContext context, RealmModel realm,
      UserModel user) {
    return context.getSession().userCredentialManager()
        .isConfiguredFor(realm, user, OTPCredentialModel.TYPE);
  }

  private boolean isMail2FaConfigured(UserModel user) {
    return parseBoolean(user.getFirstAttribute(OTP_MAIL_AUTHENTICATION_ATTRIBUTE));
  }
}
