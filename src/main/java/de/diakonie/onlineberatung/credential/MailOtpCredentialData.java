package de.diakonie.onlineberatung.credential;

public class MailOtpCredentialData {

  private long ttlInSeconds;
  private long expiry;
  private String email;
  private int failedVerifications;
  private boolean active;

  public MailOtpCredentialData(long ttlInSeconds, long expiry, String email, int failedVerifications, boolean active) {
    this.ttlInSeconds = ttlInSeconds;
    this.expiry = expiry;
    this.email = email;
    this.failedVerifications = failedVerifications;
    this.active = active;
  }

  public long getTtlInSeconds() {
    return ttlInSeconds;
  }

  public void setTtlInSeconds(long ttlInSeconds) {
    this.ttlInSeconds = ttlInSeconds;
  }

  public long getExpiry() {
    return expiry;
  }

  public void setExpiry(long expiry) {
    this.expiry = expiry;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public int getFailedVerifications() {
    return failedVerifications;
  }

  public boolean isActive() {
    return active;
  }

  public void setActive(boolean active) {
    this.active = active;
  }

  public void setFailedVerifications(int failedVerifications) {
    this.failedVerifications = failedVerifications;
  }
}
