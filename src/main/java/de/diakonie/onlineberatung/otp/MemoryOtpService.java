package de.diakonie.onlineberatung.otp;

import static de.diakonie.onlineberatung.otp.ValidationResult.EXPIRED;
import static de.diakonie.onlineberatung.otp.ValidationResult.INVALID;
import static de.diakonie.onlineberatung.otp.ValidationResult.NOT_PRESENT;
import static de.diakonie.onlineberatung.otp.ValidationResult.TOO_MANY_FAILED_ATTEMPTS;
import static de.diakonie.onlineberatung.otp.ValidationResult.VALID;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import java.time.Clock;
import java.util.Map;
import javax.annotation.Nullable;
import org.keycloak.models.AuthenticatorConfigModel;

public class MemoryOtpService implements OtpService {

  private static final int DEFAULT_TTL_IN_SECONDS = 300;
  private static final int DEFAULT_CODE_LENGTH = 6;
  private static final int MAX_FAILED_VALIDATIONS = 3;
  private static final long SECOND_IN_MILLIS = 1000L;

  private final Map<String, Otp> otpStore;
  private final OtpGenerator generator;
  private final Clock clock;

  public MemoryOtpService(Map<String, Otp> otpStore, OtpGenerator generator, Clock clock) {
    this.otpStore = otpStore;
    this.generator = generator;
    this.clock = clock;
  }

  @Override
  public Otp createOtp(@Nullable AuthenticatorConfigModel authConfig, String emailAddress) {
    var length = DEFAULT_CODE_LENGTH;
    var ttlInSeconds = DEFAULT_TTL_IN_SECONDS;
    if (nonNull(authConfig)) {
      length = Integer.parseInt(authConfig.getConfig().get("length"));
      ttlInSeconds = Integer.parseInt(authConfig.getConfig().get("ttl"));
    }
    // invalidate potential already present code
    invalidate(emailAddress);

    var code = generator.generate(length);
    var expiry = clock.millis() + (ttlInSeconds * SECOND_IN_MILLIS);
    var otp = new Otp(code, ttlInSeconds, expiry);
    otpStore.put(emailAddress.toLowerCase(), otp);
    return otp;
  }

  @Override
  public ValidationResult validate(String currentCode, String emailAddress) {
    if (isNull(currentCode) || currentCode.isBlank()) {
      return INVALID;
    }
    if (isNull(emailAddress) || emailAddress.isBlank()) {
      return NOT_PRESENT;
    }

    var sentOtp = otpStore.get(emailAddress.toLowerCase());
    if (isNull(sentOtp) || isNull(sentOtp.getCode())) {
      return NOT_PRESENT;
    }

    if (isExpired(sentOtp.getExpiry())) {
      return EXPIRED;
    }

    if (!sentOtp.getCode().equals(currentCode)) {
      if (sentOtp.incAndGetFailedVerifications() > MAX_FAILED_VALIDATIONS) {
        invalidate(emailAddress);
        return TOO_MANY_FAILED_ATTEMPTS;
      }
      return INVALID;
    }

    invalidate(emailAddress);
    return VALID;
  }

  @Override
  public void invalidate(String emailAddress) {
    if (isNull(emailAddress) || emailAddress.isBlank()) {
      return;
    }
    otpStore.remove(emailAddress.toLowerCase());
  }

  private boolean isExpired(long expiry) {
    return expiry < clock.millis();
  }

}
