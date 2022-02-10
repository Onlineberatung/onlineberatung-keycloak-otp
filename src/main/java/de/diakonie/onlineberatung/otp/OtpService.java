package de.diakonie.onlineberatung.otp;

import org.keycloak.models.AuthenticatorConfigModel;

public interface OtpService {

  ValidationResult validate(String currentCode, String username);

  void invalidate(String username);

  Otp createOtp(AuthenticatorConfigModel authConfig, String username, String emailAddress);

  Otp get(String username);
}
