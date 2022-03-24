package de.diakonie.onlineberatung.otp;

import de.diakonie.onlineberatung.credential.CredentialContext;
import de.diakonie.onlineberatung.mail.MailSendingException;

public interface OtpMailSender {

  void sendOtpCode(Otp otp,
      CredentialContext credentialContext) throws MailSendingException;

}