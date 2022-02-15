package de.diakonie.onlineberatung.otp;

import static de.diakonie.onlineberatung.otp.ValidationResult.EXPIRED;
import static de.diakonie.onlineberatung.otp.ValidationResult.INVALID;
import static de.diakonie.onlineberatung.otp.ValidationResult.NOT_PRESENT;
import static de.diakonie.onlineberatung.otp.ValidationResult.TOO_MANY_FAILED_ATTEMPTS;
import static de.diakonie.onlineberatung.otp.ValidationResult.VALID;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import de.diakonie.onlineberatung.credential.MailOtpCredentialModel;
import de.diakonie.onlineberatung.credential.MailOtpCredentialProvider;
import java.time.Clock;
import javax.annotation.Nullable;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class MemoryOtpService implements OtpService {

  private static final Logger logger = Logger.getLogger(MemoryOtpService.class);
  private static final int DEFAULT_TTL_IN_SECONDS = 300;
  private static final int DEFAULT_CODE_LENGTH = 6;
  private static final int MAX_FAILED_VALIDATIONS = 3;
  private static final long SECOND_IN_MILLIS = 1000L;

  private final MailOtpCredentialProvider credentialProvider;
  private final OtpGenerator generator;
  private final Clock clock;

  private int codeLength = DEFAULT_CODE_LENGTH;
  private int ttlInSeconds = DEFAULT_TTL_IN_SECONDS;

  public MemoryOtpService(MailOtpCredentialProvider credentialProvider, OtpGenerator generator,
      Clock clock, @Nullable AuthenticatorConfigModel authConfig) {
    this.credentialProvider = credentialProvider;
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
  public Otp createOtp(String emailAddress, boolean active) {
    var code = generator.generate(codeLength);
    var expiry = clock.millis() + (ttlInSeconds * SECOND_IN_MILLIS);
    return new Otp(code, ttlInSeconds, expiry, emailAddress, 0, active);
  }

  public MailOtpCredentialModel createCredential(Otp otp, RealmModel realm, UserModel user) {
    var credentialModel = MailOtpCredentialModel.createOtpModel(otp, clock);
    credentialProvider.createCredential(realm, user, credentialModel);
    return credentialModel;
  }

  @Override
  public MailOtpCredentialModel getCredential(KeycloakSession session, RealmModel realm,
      UserModel user) {
    return credentialProvider.getDefaultCredential(session, realm, user);
  }

  @Override
  public void activateCredential(MailOtpCredentialModel credentialModel, RealmModel realm,
      UserModel user) {
    credentialModel.setActive();
    credentialProvider.updateCredential(realm, user, credentialModel);
  }

  @Override
  public void deleteCredential(KeycloakSession session, RealmModel realm, UserModel user) {
    var credential = getCredential(session, realm, user);
    credentialProvider.deleteCredential(realm, user, credential.getId());
  }

  public void update(MailOtpCredentialModel credentialModel, RealmModel realm, UserModel user,
      Otp otp) {
    var updated = credentialModel.updateFrom(otp);
    credentialProvider.updateCredential(realm, user, updated);
  }

  @Override
  public ValidationResult validate(String currentCode, MailOtpCredentialModel credentialModel,
      RealmModel realm, UserModel user) {
    if (isNull(currentCode) || currentCode.isBlank()) {
      return INVALID;
    }

    var storedOtp = credentialModel.getOtp();
    if (isNull(storedOtp) || isNull(storedOtp.getCode()) || "INVALIDATED".equals(
        storedOtp.getCode())) {
      return NOT_PRESENT;
    }

    if (isExpired(storedOtp.getExpiry())) {
      return EXPIRED;
    }

    if (!storedOtp.getCode().equals(currentCode)) {
      var failedVerifications = storedOtp.getFailedVerifications() + 1;
      if (failedVerifications > MAX_FAILED_VALIDATIONS) {
        invalidate(credentialModel, realm, user);
        return TOO_MANY_FAILED_ATTEMPTS;
      }
      credentialModel.updateFailedVerifications(failedVerifications);
      credentialProvider.updateCredential(realm, user, credentialModel);
      return INVALID;
    }

    invalidate(credentialModel, realm, user);
    return VALID;
  }

  @Override
  public void invalidate(MailOtpCredentialModel credentialModel, RealmModel realm, UserModel user) {
    credentialModel.updateCode("INVALIDATED");
    credentialModel.updateFailedVerifications(0);
    credentialProvider.updateCredential(realm, user, credentialModel);
  }


  private boolean isExpired(long expiry) {
    return expiry < clock.millis();
  }

}
