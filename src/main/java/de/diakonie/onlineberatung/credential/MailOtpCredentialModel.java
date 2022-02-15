package de.diakonie.onlineberatung.credential;

import static org.keycloak.util.JsonSerialization.writeValueAsString;

import de.diakonie.onlineberatung.otp.Otp;
import java.io.IOException;
import java.time.Clock;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

public class MailOtpCredentialModel extends CredentialModel {

  public static final String TYPE = "MAIL_OTP_CM";

  private final MailOtpCredentialData credentialData;
  private final MailOtpSecretData secretData;

  public MailOtpCredentialModel(Otp otp) {
    this.credentialData = new MailOtpCredentialData(otp.getTtlInSeconds(), otp.getExpiry(),
        otp.getEmail(), otp.getFailedVerifications(), otp.isActive());
    this.secretData = new MailOtpSecretData(otp.getCode());
  }

  public MailOtpCredentialModel(String code, long ttlInSeconds, long expiry, String email,
      int failedVerifications, boolean active) {
    this.credentialData = new MailOtpCredentialData(ttlInSeconds, expiry, email,
        failedVerifications, active);
    this.secretData = new MailOtpSecretData(code);
  }

  public Otp getOtp() {
    return new Otp(secretData.getCode(), credentialData.getTtlInSeconds(),
        credentialData.getExpiry(), credentialData.getEmail(),
        credentialData.getFailedVerifications(), credentialData.isActive()
    );
  }

  public static MailOtpCredentialModel createOtpModel(Otp otp, Clock clock) {
    var credentialModel = new MailOtpCredentialModel(otp);
    try {
      credentialModel.setCredentialData(
          writeValueAsString(credentialModel.credentialData));
      credentialModel.setSecretData(
          writeValueAsString(credentialModel.secretData));
      credentialModel.setType(TYPE);
      credentialModel.setCreatedDate(clock.millis());
    } catch (IOException e) {
      throw new RuntimeException("failed to create MailOtpCredentialModel", e);
    }
    return credentialModel;
  }

  public MailOtpCredentialModel updateFrom(Otp otp) {
    credentialData.setEmail(otp.getEmail());
    credentialData.setFailedVerifications(otp.getFailedVerifications());
    credentialData.setActive(otp.isActive());
    credentialData.setTtlInSeconds(otp.getTtlInSeconds());
    credentialData.setExpiry(otp.getExpiry());

    secretData.setCode(otp.getCode());

    try {
      setCredentialData(writeValueAsString(credentialData));
      setSecretData(writeValueAsString(secretData));
    } catch (IOException e) {
      throw new RuntimeException("failed to create MailOtpCredentialModel", e);
    }
    return this;
  }

  public static MailOtpCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
    try {
      var credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(),
          MailOtpCredentialData.class);
      var secretData = JsonSerialization.readValue(credentialModel.getSecretData(),
          MailOtpSecretData.class);
      var otpCredentialModel = new MailOtpCredentialModel(secretData.getCode(),
          credentialData.getTtlInSeconds(), credentialData.getExpiry(), credentialData.getEmail(),
          credentialData.getFailedVerifications(), credentialData.isActive());
      otpCredentialModel.setUserLabel(otpCredentialModel.getUserLabel());
      otpCredentialModel.setCreatedDate(otpCredentialModel.getCreatedDate());
      otpCredentialModel.setType(TYPE);
      otpCredentialModel.setId(otpCredentialModel.getId());
      otpCredentialModel.setSecretData(otpCredentialModel.getSecretData());
      otpCredentialModel.setCredentialData(otpCredentialModel.getCredentialData());
      return otpCredentialModel;
    } catch (IOException e) {
      throw new RuntimeException("failed to create MailOtpCredentialModel from credential model",
          e);
    }
  }

  public void updateFailedVerifications(int failedVerifications) {
    this.credentialData.setFailedVerifications(failedVerifications);
    try {
      setCredentialData(writeValueAsString(credentialData));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public void setActive() {
    this.credentialData.setActive(true);
    try {
      setCredentialData(writeValueAsString(credentialData));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public void updateCode(String code) {
    this.secretData.setCode(code);
    try {
      setSecretData(writeValueAsString(secretData));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

}
