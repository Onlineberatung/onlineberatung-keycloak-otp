package de.diakonie.onlineberatung;

public class OtpInfoDTO {

  private boolean otpSetup;
  private String otpSecret;
  private String otpSecretQrCode;

  public OtpInfoDTO() {
  }

  public boolean isOtpSetup() {
    return otpSetup;
  }

  public void setOtpSetup(boolean otpSetup) {
    this.otpSetup = otpSetup;
  }

  public String getOtpSecret() {
    return otpSecret;
  }

  public void setOtpSecret(String otpSecret) {
    this.otpSecret = otpSecret;
  }

  public String getOtpSecretQrCode() {
    return otpSecretQrCode;
  }

  public void setOtpSecretQrCode(String otpSecretQrCode) {
    this.otpSecretQrCode = otpSecretQrCode;
  }
}
