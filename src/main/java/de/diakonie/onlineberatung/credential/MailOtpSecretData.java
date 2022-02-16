package de.diakonie.onlineberatung.credential;

public class MailOtpSecretData {

  private String code;
  private long expiry;

  public MailOtpSecretData() {
  }

  public MailOtpSecretData(String code, long expiry) {
    this.code = code;
    this.expiry = expiry;
  }

  public String getCode() {
    return code;
  }

  public void setCode(String code) {
    this.code = code;
  }


  public long getExpiry() {
    return expiry;
  }

  public void setExpiry(long expiry) {
    this.expiry = expiry;
  }
}
