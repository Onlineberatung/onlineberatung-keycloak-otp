package de.onlineberatung.mail;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.emptySet;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.otp.Otp;
import de.onlineberatung.otp.OtpMailSender;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.email.freemarker.FreeMarkerEmailTemplateProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.theme.FreeMarkerUtil;

public class DefaultMailSender implements OtpMailSender {

  private static final int MINUTE_IN_SECONDS = 60;
  private static final String OTP_MAIL_TEMPLATE = "otp-email.ftl";
  private static final String EMAIL_SUBJECT = "emailSubject";
  private static final String OTP_ATTRIBUTE = "otp";
  private static final String TTL_ATTRIBUTE = "ttl";

  @Override
  public void sendOtpCode(Otp otp, CredentialContext context) throws MailSendingException {
    try {
      var mailRecipient = createMailRecipient(otp);
      var mailAttributes = createMailAttributes(otp);
      var mailTemplateProvider = createMailTemplateProvider(context, mailRecipient);

      mailTemplateProvider.send(EMAIL_SUBJECT, emptyList(), OTP_MAIL_TEMPLATE, mailAttributes);
    } catch (Exception e) {
      throw new MailSendingException("failed to send otp mail", e);
    }
  }

  private UserModel createMailRecipient(Otp otp) {
    var mailRecipient = new MailUser();
    mailRecipient.setEmail(otp.getEmail());
    return mailRecipient;
  }

  private HashMap<String, Object> createMailAttributes(Otp otp) {
    var attributes = new HashMap<String, Object>();
    attributes.put(OTP_ATTRIBUTE, otp.getCode());
    var ttlInSeconds = otp.getTtlInSeconds() > 0 ? otp.getTtlInSeconds() : 60;
    attributes.put(TTL_ATTRIBUTE, Math.floorDiv(ttlInSeconds, MINUTE_IN_SECONDS));
    return attributes;
  }

  private EmailTemplateProvider createMailTemplateProvider(CredentialContext context,
      UserModel mailRecipient) {
    var freeMarker = new FreeMarkerUtil();
    var emailTemplateProvider = new FreeMarkerEmailTemplateProvider(context.getSession(),
        freeMarker);
    emailTemplateProvider.setRealm(context.getRealm());
    emailTemplateProvider.setUser(mailRecipient);
    return emailTemplateProvider;
  }

  // DefaultEmailSenderProvider just needs the email of the user, yet asks for the whole model
  private static class MailUser implements UserModel {

    private String emailAddress;

    @Override
    public String getId() {
      return null;
    }

    @Override
    public String getUsername() {
      return null;
    }

    @Override
    public void setUsername(String username) {
      // unused
    }

    @Override
    public Long getCreatedTimestamp() {
      return null;
    }

    @Override
    public void setCreatedTimestamp(Long timestamp) {
      // unused
    }

    @Override
    public boolean isEnabled() {
      return false;
    }

    @Override
    public void setEnabled(boolean enabled) {
      // unused
    }

    @Override
    public void setSingleAttribute(String name, String value) {
      // unused
    }

    @Override
    public void setAttribute(String name, List<String> values) {
      // unused
    }

    @Override
    public void removeAttribute(String name) {
      // unused
    }

    @Override
    public String getFirstAttribute(String name) {
      return null;
    }

    @Override
    public List<String> getAttribute(String name) {
      return emptyList();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
      return emptyMap();
    }

    @Override
    public Set<String> getRequiredActions() {
      return emptySet();
    }

    @Override
    public void addRequiredAction(String action) {
      // unused
    }

    @Override
    public void removeRequiredAction(String action) {
      // unused
    }

    @Override
    public String getFirstName() {
      return null;
    }

    @Override
    public void setFirstName(String firstName) {
      // unused
    }

    @Override
    public String getLastName() {
      return null;
    }

    @Override
    public void setLastName(String lastName) {
      // unused
    }

    @Override
    public String getEmail() {
      return emailAddress;
    }

    @Override
    public void setEmail(String email) {
      emailAddress = email;
    }

    @Override
    public boolean isEmailVerified() {
      return false;
    }

    @Override
    public void setEmailVerified(boolean verified) {
      // unused
    }

    @Override
    public Set<GroupModel> getGroups() {
      return emptySet();
    }

    @Override
    public void joinGroup(GroupModel group) {
      // unused
    }

    @Override
    public void leaveGroup(GroupModel group) {
      // unused
    }

    @Override
    public boolean isMemberOf(GroupModel group) {
      return false;
    }

    @Override
    public String getFederationLink() {
      return null;
    }

    @Override
    public void setFederationLink(String link) {
      // unused
    }

    @Override
    public String getServiceAccountClientLink() {
      return null;
    }

    @Override
    public void setServiceAccountClientLink(String clientInternalId) {
      // unused
    }

    @Override
    public Set<RoleModel> getRealmRoleMappings() {
      return emptySet();
    }

    @Override
    public Set<RoleModel> getClientRoleMappings(ClientModel app) {
      return emptySet();
    }

    @Override
    public boolean hasRole(RoleModel role) {
      return false;
    }

    @Override
    public void grantRole(RoleModel role) {
      // unused
    }

    @Override
    public Set<RoleModel> getRoleMappings() {
      return emptySet();
    }

    @Override
    public void deleteRoleMapping(RoleModel role) {
      // unused
    }
  }
}

