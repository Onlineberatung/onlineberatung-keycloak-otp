package de.diakonie.onlineberatung.otp;

import java.util.Objects;

public class Otp {

  private final String code;
  private final long ttlInSeconds;
  private final long expiry;
  private final String email;
  private final int failedVerifications;
  private final boolean active;

  public Otp(String code, long ttlInSeconds, long expiry, String email, int failedVerifications,
      boolean active) {
    this.code = code;
    this.ttlInSeconds = ttlInSeconds;
    this.expiry = expiry;
    this.email = email;
    this.active = active;
    this.failedVerifications = failedVerifications;
  }

  public String getCode() {
    return code;
  }

  public long getTtlInSeconds() {
    return ttlInSeconds;
  }

  public long getExpiry() {
    return expiry;
  }

  public String getEmail() {
    return email;
  }

  public int getFailedVerifications() {
    return failedVerifications;
  }

  public boolean isActive() {
    return active;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Otp otp = (Otp) o;
    return ttlInSeconds == otp.ttlInSeconds && expiry == otp.expiry
        && failedVerifications == otp.failedVerifications && active == otp.active
        && Objects.equals(code, otp.code) && Objects.equals(email, otp.email);
  }

  @Override
  public int hashCode() {
    return Objects.hash(code, ttlInSeconds, expiry, email, failedVerifications, active);
  }

  @Override
  public String toString() {
    return "Otp{" +
        "code='" + code + '\'' +
        ", ttlInSeconds=" + ttlInSeconds +
        ", expiry=" + expiry +
        ", email='" + email + '\'' +
        ", failedVerifications=" + failedVerifications +
        ", active=" + active +
        '}';
  }
}
