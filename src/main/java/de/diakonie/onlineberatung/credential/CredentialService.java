package de.diakonie.onlineberatung.credential;

import de.diakonie.onlineberatung.otp.Otp;

public interface CredentialService {

  MailOtpCredentialModel createCredential(Otp otp, CredentialContext context);

  void update(MailOtpCredentialModel credentialModel, CredentialContext context);

  MailOtpCredentialModel getCredential(CredentialContext context);

  void deleteCredential(CredentialContext context);

  void invalidate(MailOtpCredentialModel credentialModel, CredentialContext context);
}
