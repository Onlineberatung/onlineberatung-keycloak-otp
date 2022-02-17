package de.diakonie.onlineberatung.credential;

import de.diakonie.onlineberatung.otp.Otp;
import java.time.Clock;

public class MailOtpCredentialService implements CredentialService {

  private final MailOtpCredentialProvider credentialProvider;
  private final Clock clock;

  public MailOtpCredentialService(MailOtpCredentialProvider credentialProvider, Clock clock) {
    this.credentialProvider = credentialProvider;
    this.clock = clock;
  }

  @Override
  public MailOtpCredentialModel createCredential(Otp otp, CredentialContext context) {
    var credentialModel = MailOtpCredentialModel.createOtpModel(otp, clock, false);
    credentialProvider.createCredential(context.getRealm(), context.getUser(), credentialModel);
    return credentialModel;
  }

  @Override
  public void update(MailOtpCredentialModel credentialModel, CredentialContext context) {
    credentialProvider.updateCredential(context.getRealm(), context.getUser(), credentialModel);
  }

  @Override
  public MailOtpCredentialModel getCredential(CredentialContext context) {
    return credentialProvider.getDefaultCredential(context.getSession(), context.getRealm(),
        context.getUser());
  }

  @Override
  public void deleteCredential(CredentialContext context) {
    var credential = getCredential(context);
    credentialProvider.deleteCredential(context.getRealm(), context.getUser(), credential.getId());
  }

  @Override
  public void invalidate(MailOtpCredentialModel credentialModel, CredentialContext context) {
    credentialModel.updateCode(MailOtpCredentialModel.INVALIDATED);
    credentialProvider.updateCredential(context.getRealm(), context.getUser(), credentialModel);
  }
}
