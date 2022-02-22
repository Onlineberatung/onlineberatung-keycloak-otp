package de.diakonie.onlineberatung.credential;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import de.diakonie.onlineberatung.otp.Otp;
import java.time.Clock;

public class MailOtpCredentialService {

  private final MailOtpCredentialProvider credentialProvider;
  private final Clock clock;

  public MailOtpCredentialService(MailOtpCredentialProvider credentialProvider, Clock clock) {
    this.credentialProvider = credentialProvider;
    this.clock = clock;
  }

  public MailOtpCredentialModel createCredential(Otp otp, CredentialContext context) {
    var credentialModel = MailOtpCredentialModel.createOtpModel(otp, clock, false);
    credentialProvider.createCredential(context.getRealm(), context.getUser(), credentialModel);
    return credentialModel;
  }

  public void update(MailOtpCredentialModel credentialModel, CredentialContext context) {
    credentialProvider.updateCredential(context.getRealm(), context.getUser(), credentialModel);
  }

  public MailOtpCredentialModel getCredential(CredentialContext context) {
    return credentialProvider.getDefaultCredential(context.getSession(), context.getRealm(),
        context.getUser());
  }

  public void deleteCredential(CredentialContext context) {
    var credential = getCredential(context);
    if (isNull(credential)) {
      return;
    }
    credentialProvider.deleteCredential(context.getRealm(), context.getUser(), credential.getId());
  }

  public void invalidate(MailOtpCredentialModel credentialModel, CredentialContext context) {
    credentialModel.updateCode(MailOtpCredentialModel.INVALIDATED);
    credentialProvider.updateCredential(context.getRealm(), context.getUser(), credentialModel);
  }

  public boolean is2FAConfigured(CredentialContext context) {
    var credential = getCredential(context);
    return nonNull(credential) && credential.isActive();
  }
}
