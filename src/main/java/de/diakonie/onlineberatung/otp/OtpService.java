package de.diakonie.onlineberatung.otp;

public interface OtpService {

  ValidationResult validate(String currentCode, String username);

  void invalidate(String username);

  Otp createOtp(String username, String emailAddress);

  Otp get(String username);
}
