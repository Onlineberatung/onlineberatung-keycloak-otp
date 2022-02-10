package de.diakonie.onlineberatung.otp;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

public class Otp {

  private final String code;
  private final long ttlInSeconds;
  private final long expiry;
  private final String email;
  private final AtomicInteger failedVerifications;

  public Otp(String code, long ttlInSeconds, long expiry, String email) {
    this.code = code;
    this.ttlInSeconds = ttlInSeconds;
    this.expiry = expiry;
    this.email = email;
    this.failedVerifications = new AtomicInteger();
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

  public int incAndGetFailedVerifications() {
    return failedVerifications.incrementAndGet();
  }

  public String getEmail() {
    return email;
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
    return ttlInSeconds == otp.ttlInSeconds && expiry == otp.expiry && Objects.equals(code,
        otp.code) && Objects.equals(email, otp.email)
        && failedVerifications.get() == otp.failedVerifications.get();
  }

  @Override
  public int hashCode() {
    return Objects.hash(code, ttlInSeconds, expiry, email, failedVerifications.get());
  }

  @Override
  public String toString() {
    return "Otp{" +
        "code='" + code + '\'' +
        ", ttlInSeconds=" + ttlInSeconds +
        ", expiry=" + expiry +
        ", email='" + email + '\'' +
        ", failedVerifications=" + failedVerifications.get() +
        '}';
  }

}
