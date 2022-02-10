package de.diakonie.onlineberatung.otp;

import static de.diakonie.onlineberatung.otp.ValidationResult.INVALID;
import static de.diakonie.onlineberatung.otp.ValidationResult.NOT_PRESENT;
import static de.diakonie.onlineberatung.otp.ValidationResult.TOO_MANY_FAILED_ATTEMPTS;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.diakonie.onlineberatung.otp.MemoryOtpService;
import de.diakonie.onlineberatung.otp.Otp;
import de.diakonie.onlineberatung.otp.OtpGenerator;
import de.diakonie.onlineberatung.otp.OtpStore;
import de.diakonie.onlineberatung.otp.ValidationResult;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.models.AuthenticatorConfigModel;

public class MemoryOtpServiceTest {

  private OtpStore otpStore;
  private MemoryOtpService memoryOtpService;
  private OtpGenerator otpGenerator;
  private Clock fixed;

  @Before
  public void setUp() {
    fixed = Clock.fixed(LocalDateTime.of(2022, 2, 3, 13, 13, 0).toInstant(ZoneOffset.UTC),
        ZoneId.of("UTC"));
    otpStore = new TestOtpStore(new HashMap<>());
    otpGenerator = mock(OtpGenerator.class);
    memoryOtpService = new MemoryOtpService(otpStore, otpGenerator, fixed);
  }

  @Test
  public void should_create_and_store_otp_with_default_ttl_and_expiry() {
    when(otpGenerator.generate(6)).thenReturn("123456");

    var otp = memoryOtpService.createOtp(null, "Ansgar", "hk@test.de");

    var expected = new Otp("123456", 300, 1643894280000L, "hk@test.de");
    assertThat(otpStore.get("ansgar")).isEqualTo(expected);
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
    when(otpGenerator.generate(8)).thenReturn("12345678");

    var otp = memoryOtpService.createOtp(authConfig, "Ansgar", "hk@test.de");

    var expected = new Otp("12345678", 500, 1643894480000L, "hk@test.de");
    assertThat(memoryOtpService.get("Ansgar")).isEqualTo(expected);
    assertThat(otp).isEqualTo(expected);
  }

  @Test
  public void validate_should_be_valid_if_otp_stored_equals_current_and_is_not_expired() {
    otpStore.put("creativeusername", new Otp("4711", 300, fixed.millis() + 1000, "hk@test.de"));

    var result = memoryOtpService.validate("4711", "creativeusername");

    assertThat(result).isEqualTo(ValidationResult.VALID);
    assertThat(memoryOtpService.validate("4711", "creativeusername")).isEqualTo(NOT_PRESENT);
  }

  @Test
  public void validate_should_be_not_present_if_otp_was_not_stored() {
    var result = memoryOtpService.validate("4711", "creativeUsername");

    assertThat(result).isEqualTo(NOT_PRESENT);
  }

  @Test
  public void validate_should_return_expired_if_otp_is_expired() {
    otpStore.put("creativeusername", new Otp("4711", 3000, fixed.millis() - 1000, "hk@test.de"));

    var result = memoryOtpService.validate("4711", "creativeusername");

    assertThat(result).isEqualTo(ValidationResult.EXPIRED);
  }

  @Test
  public void validate_should_be_invalid_if_stored_otp_does_not_equal_current() {
    otpStore.put("creativeusername", new Otp("1234", 3000, fixed.millis() + 1000, "hk@test.de"));

    var result = memoryOtpService.validate("4711", "creativeusername");

    assertThat(result).isEqualTo(INVALID);
  }

  @Test
  public void validate_should_be_invalid_on_empty_or_null_current_code() {
    assertThat(memoryOtpService.validate(null, "creativeusername")).isEqualTo(INVALID);
    assertThat(memoryOtpService.validate("", "creativeusername")).isEqualTo(INVALID);
  }

  @Test
  public void validate_should_be_not_present_if_email_is_null_or_empty() {
    assertThat(memoryOtpService.validate("123", "")).isEqualTo(NOT_PRESENT);
    assertThat(memoryOtpService.validate("1234", null)).isEqualTo(NOT_PRESENT);
  }

  @Test
  public void validate_should_invalidate_otp_after_three_failed_validations() {
    otpStore.put("creativeusername", new Otp("4711", 300, fixed.millis() + 1000, "hk@test.de"));

    assertThat(memoryOtpService.validate("1", "creativeusername")).isEqualTo(INVALID);
    assertThat(memoryOtpService.validate("2", "creativeusername")).isEqualTo(INVALID);
    assertThat(memoryOtpService.validate("3", "creativeusername")).isEqualTo(INVALID);
    assertThat(memoryOtpService.validate("4", "creativeusername")).isEqualTo(TOO_MANY_FAILED_ATTEMPTS);
    assertThat(memoryOtpService.validate("4711", "creativeusername")).isEqualTo(NOT_PRESENT);
  }

  private static class TestOtpStore implements OtpStore {

    private final Map<String, Otp> store;

    TestOtpStore(Map<String, Otp> store) {
      this.store = store;
    }

    @Override
    public void put(String key, Otp otp) {
      store.put(key, otp);
    }

    @Override
    public Otp get(String key) {
      return store.get(key);
    }

    @Override
    public void remove(String key) {
      store.remove(key);
    }
  }
}