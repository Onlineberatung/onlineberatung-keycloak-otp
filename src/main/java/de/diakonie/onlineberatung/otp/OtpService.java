package de.diakonie.onlineberatung.otp;

public interface OtpService {

  ValidationResult validate(String currentCode, Otp otp);

  Otp createOtp(String emailAddress);

}
