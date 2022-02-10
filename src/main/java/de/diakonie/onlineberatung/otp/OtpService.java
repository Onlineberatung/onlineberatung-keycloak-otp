package de.diakonie.onlineberatung.otp;

import org.keycloak.models.AuthenticatorConfigModel;

public interface OtpService {

  ValidationResult validate(String currentCode, String emailAddress);

  void invalidate(String emailAddress);

  Otp createOtp(AuthenticatorConfigModel authConfig, String emailAddress);
}
