package de.diakonie.onlineberatung.otp;

import static de.diakonie.onlineberatung.otp.ValidationResult.EXPIRED;
import static de.diakonie.onlineberatung.otp.ValidationResult.INVALID;
import static de.diakonie.onlineberatung.otp.ValidationResult.NOT_PRESENT;
import static de.diakonie.onlineberatung.otp.ValidationResult.TOO_MANY_FAILED_ATTEMPTS;
import static de.diakonie.onlineberatung.otp.ValidationResult.VALID;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import de.diakonie.onlineberatung.credential.MailOtpCredentialModel;
import java.time.Clock;
import javax.annotation.Nullable;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;

public class MemoryOtpService implements OtpService {

  private static final Logger logger = Logger.getLogger(MemoryOtpService.class);
  private static final int DEFAULT_TTL_IN_SECONDS = 900;
  private static final int DEFAULT_CODE_LENGTH = 6;
  private static final int MAX_FAILED_VALIDATIONS = 3;
  private static final long SECOND_IN_MILLIS = 1000L;

  private final OtpGenerator generator;
  private final Clock clock;

  private int codeLength = DEFAULT_CODE_LENGTH;
  private int ttlInSeconds = DEFAULT_TTL_IN_SECONDS;

  public MemoryOtpService(OtpGenerator generator, Clock clock,
      @Nullable AuthenticatorConfigModel authConfig) {
    this.generator = generator;
    this.clock = clock;
    if (nonNull(authConfig)) {
      try {
        codeLength = Integer.parseInt(authConfig.getConfig().get("length"));
        ttlInSeconds = Integer.parseInt(authConfig.getConfig().get("ttl"));
      } catch (Exception e) {
        logger.warn("failed to load otp length and ttl from auth config " + authConfig.getAlias()
            + ". Using default.");
        codeLength = DEFAULT_CODE_LENGTH;
        ttlInSeconds = DEFAULT_TTL_IN_SECONDS;
      }
    }
  }

  @Override
  public Otp createOtp(String emailAddress) {
    var code = generator.generate(codeLength);
    var expiry = clock.millis() + (ttlInSeconds * SECOND_IN_MILLIS);
    return new Otp(code, ttlInSeconds, expiry, emailAddress, 0);
  }

  @Override
  public ValidationResult validate(String currentCode, Otp storedOtp) {
    if (isNull(currentCode) || currentCode.isBlank()) {
      return INVALID;
    }

    if (isNull(storedOtp) || isNull(storedOtp.getCode())
        || MailOtpCredentialModel.INVALIDATED.equals(storedOtp.getCode())) {
      return NOT_PRESENT;
    }

    if (storedOtp.getFailedVerifications() >= MAX_FAILED_VALIDATIONS) {
      return TOO_MANY_FAILED_ATTEMPTS;
    }

    if (isExpired(storedOtp.getExpiry())) {
      return EXPIRED;
    }

    if (!storedOtp.getCode().equals(currentCode)) {
      return INVALID;
    }

    return VALID;
  }

  private boolean isExpired(long expiry) {
    return expiry < clock.millis();
  }

}
