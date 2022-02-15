package de.diakonie.onlineberatung.otp;

import static de.diakonie.onlineberatung.otp.ValidationResult.INVALID;
import static de.diakonie.onlineberatung.otp.ValidationResult.NOT_PRESENT;
import static de.diakonie.onlineberatung.otp.ValidationResult.TOO_MANY_FAILED_ATTEMPTS;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.diakonie.onlineberatung.credential.MailOtpCredentialModel;
import de.diakonie.onlineberatung.credential.MailOtpCredentialProvider;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashMap;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class MemoryOtpServiceTest {

  private MailOtpCredentialProvider mailOtpCredentialProvider;
  private OtpGenerator otpGenerator;
  private Clock fixed;

  private MemoryOtpService memoryOtpService;
  private RealmModel realm;
  private UserModel user;

  @Before
  public void setUp() {
    realm = mock(RealmModel.class);
    user = mock(UserModel.class);
    mailOtpCredentialProvider = mock(MailOtpCredentialProvider.class);
    fixed = Clock.fixed(LocalDateTime.of(2022, 2, 3, 13, 13, 0).toInstant(ZoneOffset.UTC),
        ZoneId.of("UTC"));
    otpGenerator = mock(OtpGenerator.class);
    memoryOtpService = new MemoryOtpService(mailOtpCredentialProvider, otpGenerator, fixed, null);
  }

  @Test
  public void should_create_otp_with_default_ttl_and_expiry() {
    when(otpGenerator.generate(6)).thenReturn("123456");

    var otp = memoryOtpService.createOtp("hk@test.de", true);

    var expected = new Otp("123456", 300, 1643894280000L, "hk@test.de", 0,true);
    verify(otpGenerator).generate(6);
    assertThat(otp).isEqualTo(expected);
  }

  @Test
  public void should_use_auth_config_if_given() {
    var authConfig = mock(AuthenticatorConfigModel.class);
    var internalConfig = new HashMap<String, String>();
    when(authConfig.getConfig()).thenReturn(internalConfig);
    internalConfig.put("ttl", "500");
    internalConfig.put("length", "8");
    memoryOtpService = new MemoryOtpService(mailOtpCredentialProvider, otpGenerator, fixed,
        authConfig);
    when(otpGenerator.generate(8)).thenReturn("12345678");

    var otp = memoryOtpService.createOtp("hk@test.de", true);

    var expected = new Otp("12345678", 500, 1643894480000L, "hk@test.de", 0,true);
    assertThat(otp).isEqualTo(expected);
  }

  @Test
  public void validate_should_be_valid_if_otp_equals_current_and_is_not_expired() {
    var credentialModel = MailOtpCredentialModel.createOtpModel(
        new Otp("4711", 300, fixed.millis() + 1000, null, 0,true),
        Clock.systemDefaultZone());

    var result = memoryOtpService.validate("4711", credentialModel, realm, user);

    assertThat(result).isEqualTo(ValidationResult.VALID);
  }

  @Test
  public void validate_should_be_not_present_if_otp_was_not_stored() {
    var credentialModel = MailOtpCredentialModel.createOtpModel(
        new Otp("INVALIDATED", 300, fixed.millis() + 1000, null, 0,true),
        Clock.systemDefaultZone());
    var result = memoryOtpService.validate("4711", credentialModel, realm, user);

    assertThat(result).isEqualTo(NOT_PRESENT);
  }

  @Test
  public void validate_should_return_expired_if_otp_is_expired() {
    var credentialModel = MailOtpCredentialModel.createOtpModel(
        new Otp("4711", 3000L, fixed.millis() - 1000, null, 0,true),
        Clock.systemDefaultZone());

    var result = memoryOtpService.validate("4711", credentialModel, realm, user);

    assertThat(result).isEqualTo(ValidationResult.EXPIRED);
  }

  @Test
  public void validate_should_be_invalid_if_stored_otp_does_not_equal_current() {
    var credentialModel = MailOtpCredentialModel.createOtpModel(
        new Otp("1234", 300, fixed.millis() + 1000, null, 0,true),
        Clock.systemDefaultZone());

    var result = memoryOtpService.validate("4711", credentialModel, realm, user);

    assertThat(result).isEqualTo(INVALID);
  }

  @Test
  public void validate_should_be_invalid_on_empty_or_null_current_code() {
    var credentialModel = MailOtpCredentialModel.createOtpModel(
        new Otp("1234", 300, fixed.millis() + 1000, null, 0,true),
        Clock.systemDefaultZone());

    assertThat(memoryOtpService.validate("", credentialModel, realm, user)).isEqualTo(INVALID);
    assertThat(memoryOtpService.validate(null, credentialModel, realm, user)).isEqualTo(INVALID);
  }

  @Test
  public void validate_should_invalidate_otp_after_three_failed_validations() {
    var credentialModel = MailOtpCredentialModel.createOtpModel(
        new Otp("1234", 300, fixed.millis() + 1000, null, 0,true),
        Clock.systemDefaultZone());

    assertThat(memoryOtpService.validate("1", credentialModel, realm, user)).isEqualTo(INVALID);
    assertThat(memoryOtpService.validate("2", credentialModel, realm, user)).isEqualTo(INVALID);
    assertThat(memoryOtpService.validate("3", credentialModel, realm, user)).isEqualTo(INVALID);
    assertThat(memoryOtpService.validate("4", credentialModel, realm, user)).isEqualTo(TOO_MANY_FAILED_ATTEMPTS);
  }

}