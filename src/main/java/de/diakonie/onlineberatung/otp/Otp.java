package de.diakonie.onlineberatung.otp;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

public class Otp {

  private final String code;
  private final long ttlInSeconds;
  private final long expiry;
  private final AtomicInteger failedVerifications;

  public Otp(String code, long ttlInSeconds, long expiry) {
    this.code = code;
    this.ttlInSeconds = ttlInSeconds;
    this.expiry = expiry;
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
        otp.code) && failedVerifications.get() == otp.failedVerifications.get();
  }

  @Override
  public int hashCode() {
    return Objects.hash(code, ttlInSeconds, expiry, failedVerifications.get());
  }

  @Override
  public String toString() {
    return "Otp{" +
        "code='" + code + '\'' +
        ", ttlInSeconds=" + ttlInSeconds +
        ", expiry=" + expiry +
        ", failedVerifications=" + failedVerifications.get() +
        '}';
  }

}
