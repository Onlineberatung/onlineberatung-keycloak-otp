package de.diakonie.onlineberatung.credential;

public class MailOtpSecretData {

  public MailOtpSecretData(String code) {
    this.code = code;
  }

  private String code;

  public String getCode() {
    return code;
  }

  public void setCode(String code) {
    this.code = code;
  }
}
