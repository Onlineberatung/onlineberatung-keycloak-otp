package de.diakonie.onlineberatung;

public class OtpSetupDTO {

  private String secret;
  private String initialCode;

  public OtpSetupDTO(String secret, String initialCode) {
    this.secret = secret;
    this.initialCode = initialCode;
  }

  public String getSecret() {
    return secret;
  }

  public void setSecret(String secret) {
    this.secret = secret;
  }

  public String getInitialCode() {
    return initialCode;
  }

  public void setInitialCode(String initialCode) {
    this.initialCode = initialCode;
  }
}
