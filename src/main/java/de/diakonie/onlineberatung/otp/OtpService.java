package de.diakonie.onlineberatung.otp;

import de.diakonie.onlineberatung.credential.MailOtpCredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public interface OtpService {

  ValidationResult validate(String currentCode, MailOtpCredentialModel credentialModel,
      RealmModel realm,
      UserModel user);

  void invalidate(MailOtpCredentialModel credentialModel, RealmModel realm, UserModel user);

  Otp createOtp(String emailAddress, boolean active);

  MailOtpCredentialModel createCredential(Otp otp, RealmModel realm, UserModel user);

  void update(MailOtpCredentialModel credentialModel, RealmModel realm, UserModel user,
      Otp code);

  MailOtpCredentialModel getCredential(KeycloakSession session, RealmModel realm, UserModel user);

  void activateCredential(MailOtpCredentialModel credentialModel, RealmModel realm, UserModel user);

  void deleteCredential(KeycloakSession session, RealmModel realm, UserModel user);
}
